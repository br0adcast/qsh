"""Injected query evaluator tests; never load libselinux or query host policy."""
import contextlib
import dataclasses
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'packaging/selinux'))
import qshd_selinux_queries as queries

CONTEXTS = (
    ('I', 'system_u:system_r:init_t:s0'),
    ('D', 'system_u:system_r:qshd_t:s0'),
    ('E', 'system_u:object_r:qshd_exec_t:s0'),
    ('C', 'system_u:object_r:qshd_config_t:s0'),
    ('L', 'system_u:object_r:qshd_log_t:s0'),
    ('R', 'system_u:object_r:qshd_runtime_t:s0'),
    ('P', 'system_u:object_r:qshd_devpts_t:s0'),
    ('U', 'user_u:user_r:user_t:s0'),
    ('T', 'user_u:object_r:user_devpts_t:s0'),
    ('S', 'system_u:object_r:shell_exec_t:s0'),
    ('V', 'system_u:object_r:devpts_t:s0'),
)
C = dict(CONTEXTS)
# Independent reviewed expected call evidence, not derived from product matrix.
ROWS = (
    ('launch-result', 'compute_create', 'I E process D'),
    ('launch-transition', 'require_av', 'I D process transition'),
    ('launch-execute', 'require_av', 'I E file getattr open read execute'),
    ('launch-entry', 'require_av', 'D E file entrypoint'),
    ('pam-self', 'require_av', 'D D process setexec setkeycreate setsched'),
    ('helper-caps', 'require_av', 'D D capability setuid setgid chown kill fowner'),
    ('helper-process', 'require_av', 'D D process fork sigchld signal sigkill setpgid'),
    ('helper-socketpair', 'require_av', 'D D unix_stream_socket create connectto read write setopt shutdown'),
    ('udp-self', 'require_av', 'D D udp_socket create bind getattr read write getopt setopt'),
    ('session-transition', 'require_av', 'D U process transition'),
    ('session-execute', 'require_av', 'D S file getattr open read execute'),
    ('session-entry', 'require_av', 'U S file entrypoint'),
    ('pty-create-result', 'compute_create', 'D V chr_file P'),
    ('pty-owned', 'require_av', 'D P chr_file open read write getattr ioctl setattr relabelfrom relabelto'),
    ('pty-user', 'require_av', 'D T chr_file open read write getattr ioctl setattr relabelfrom relabelto'),
    ('pty-select-result', 'compute_relabel', 'U P chr_file T'),
    ('pty-select-valid', 'validate_transition', 'P T chr_file D'),
    ('pty-restore-valid', 'validate_transition', 'T P chr_file D'),
    ('config-dir', 'require_av', 'D C dir create open read getattr search write add_name remove_name'),
    ('config-file', 'require_av', 'D C file create open read write getattr setattr rename unlink'),
    ('log-dir', 'require_av', 'D L dir create open read getattr search write add_name remove_name'),
    ('log-file', 'require_av', 'D L file create open read write append getattr setattr rename unlink'),
    ('runtime-dir', 'require_av', 'D R dir create open read getattr search write add_name remove_name rmdir'),
    ('runtime-file', 'require_av', 'D R file create open read write getattr setattr unlink lock'),
    ('runtime-socket-file', 'require_av', 'D R sock_file create open read write getattr setattr rename unlink'),
)

def expected_calls():
    result = [('check_context', (value,)) for _, value in CONTEXTS]
    for _, method, words in ROWS:
        source, target, cls, *tail = words.split()
        args = (C[source], C[target], cls)
        if method == 'require_av': args += (tuple(tail),)
        elif method == 'validate_transition': args += (C[tail[0]],)
        result.append((method, args))
    return result

class FakeApi:
    def __init__(self, fail=None, status_fail=None, wrong=None):
        self.calls = []; self.events = []; self.active = False
        self.fail = fail; self.status_fail = status_fail; self.wrong = wrong

    @contextlib.contextmanager
    def status_observation(self):
        self.events.append('open')
        if self.status_fail == 'open': raise RuntimeError('status setup')
        self.active = True
        try:
            yield
            self.events.append('finalize')
            if self.status_fail == 'exit': raise RuntimeError('status drift')
        finally:
            self.active = False; self.events.append('close')

    def call(self, method, *args):
        assert self.active, 'query outside status window'
        index = len(self.calls); self.calls.append((method, args))
        if self.fail == index: raise RuntimeError('private raw native diagnostic')
        if method.startswith('compute_'):
            if self.wrong == index: return C['T'] + ':c1'
            return {11: C['D'], 23: C['P'], 26: C['T']}[index]

    def check_context(self, *args): return self.call('check_context', *args)
    def require_av(self, *args): return self.call('require_av', *args)
    def compute_create(self, *args): return self.call('compute_create', *args)
    def compute_relabel(self, *args): return self.call('compute_relabel', *args)
    def validate_transition(self, *args): return self.call('validate_transition', *args)

class QueryTests(unittest.TestCase):
    def test_complete_order_and_caller_inside_single_window(self):
        api = FakeApi()
        with queries.required_observation(api) as record:
            self.assertTrue(api.active)
            self.assertEqual(api.events, ['open'])
            self.assertEqual(api.calls, expected_calls())
            self.assertEqual(record.profile_version, 1)
            self.assertEqual(record.context_ids, tuple('context-' + k for k, _ in CONTEXTS))
            self.assertEqual(record.query_ids, tuple(row[0] for row in ROWS))
            with self.assertRaises((AttributeError, dataclasses.FrozenInstanceError)):
                record.profile_version = 2
            self.assertFalse(hasattr(record, 'passed'))
            api.events.append('caller-observation')
        self.assertEqual(api.events, ['open', 'caller-observation', 'finalize', 'close'])
        self.assertFalse(api.active)

    def test_every_failure_has_bounded_id_and_stops(self):
        ids = ['context-' + k for k, _ in CONTEXTS] + [row[0] for row in ROWS]
        for index, identifier in enumerate(ids):
            with self.subTest(identifier=identifier):
                api = FakeApi(fail=index)
                with self.assertRaises(queries.QueryError) as caught:
                    with queries.required_observation(api): self.fail('must not yield')
                self.assertEqual(caught.exception.query_id, identifier)
                self.assertEqual(caught.exception.category, 'query-error')
                self.assertNotIn('private', str(caught.exception))
                self.assertIsNone(caught.exception.__cause__)
                self.assertEqual(len(api.calls), index + 1)
                self.assertEqual(api.events, ['open', 'close'])

    def test_exact_complete_computed_contexts(self):
        for index, identifier in ((11, 'launch-result'), (23, 'pty-create-result'), (26, 'pty-select-result')):
            with self.subTest(identifier=identifier):
                api = FakeApi(wrong=index)
                with self.assertRaises(queries.QueryError) as caught:
                    with queries.required_observation(api): self.fail('must not yield')
                self.assertEqual(caught.exception.query_id, identifier)
                self.assertEqual(caught.exception.category, 'unexpected-context')
                self.assertEqual(len(api.calls), index + 1)

    def test_status_setup_and_finalization_propagate(self):
        for stage in ('open', 'exit'):
            api = FakeApi(status_fail=stage)
            with self.assertRaises(RuntimeError):
                with queries.required_observation(api): self.assertTrue(api.active)
            self.assertFalse(api.active)
            self.assertEqual(len(api.calls), 0 if stage == 'open' else 36)

    def test_caller_exception_propagates_after_cleanup(self):
        api = FakeApi(); original = ValueError('caller')
        with self.assertRaises(ValueError) as caught:
            with queries.required_observation(api): raise original
        self.assertIs(caught.exception, original)
        self.assertEqual(api.events, ['open', 'close'])

if __name__ == '__main__': unittest.main()
