"""Offline causal controls; no guest APIs, package transaction or VM invocation."""
import copy
import hashlib
import importlib.util
import json
import os
import subprocess
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


DRIVER = Path(__file__).with_name('selinux_pair_acceptance.py')


def rooted_manifest_fixture(root, case='lifecycle'):
    """Real descriptor-bound admission fixture; bytes are synthetic, never run."""
    root.mkdir(parents=True, exist_ok=True)
    driver = root / 'selinux_pair_acceptance.py'
    driver.write_bytes(DRIVER.read_bytes())
    spec = importlib.util.spec_from_file_location('qsh57_admission_fixture_' + case.replace('-', '_'), driver)
    d = importlib.util.module_from_spec(spec); sys.modules[spec.name] = d; spec.loader.exec_module(d)
    inputs = {}
    names = {'driver': driver.name, 'owner': 'qshd_selinux_process.py', 'api': 'qshd_selinux_api.py',
             'first-public': 'first.pub', 'second-public': 'second.pub'}
    for v in ('A', 'B'):
        for role, suffix in (('provider', 'provider.rpm'), ('consumer', 'consumer.rpm'), ('core', 'core.pp'), ('contexts', 'contexts.pp')):
            names[v+'-'+role] = v+'.'+suffix
    for role, name in names.items():
        path = root/name
        if role != 'driver': path.write_bytes(('synthetic-' + role).encode())
        inputs[role] = dict(path=str(path), size=path.stat().st_size, sha256=d.digest(path.read_bytes()))
    artifacts = {}
    for v, release in (('A', '1'), ('B', '2')):
        identity = dict(provider_version='0.3.0', manifest_sha256=d.digest(v.encode()),
                        core_pp_sha256=inputs[v+'-core']['sha256'], contexts_pp_sha256=inputs[v+'-contexts']['sha256'])
        provider = {path: dict(size=1, sha256='a'*64, mode=0o100644, flags=0)
                    for path in d.PROVIDER_RUNTIME | {'/usr/share/qshd-selinux/hook'+str(i) for i in range(4)}}
        for role, name in (('owner', 'qshd_selinux_process.py'), ('api', 'qshd_selinux_api.py')):
            provider['/usr/libexec/qshd-selinux/'+name]['sha256'] = inputs[role]['sha256']
        consumer = {path: dict(size=1, sha256='b'*64, mode=0o100644, flags=0) for path in d.CONSUMER_FILES}
        consumer[d.PAM].update(sha256=d.PAM_SHA256, flags=17)
        artifacts[v] = dict(identity=identity, nevra=dict(provider='qshd-selinux-0.5.0-'+release+'.fc44.noarch',
            consumer='qshd-0.5.0-'+release+'.fc44.x86_64'), scripts={r:{h:'c'*64 for h in d.HOOKS} for r in ('provider','consumer')},
            files=dict(provider=provider,consumer=consumer))
    runtime = {p:'d'*64 for p in ('/usr/bin/rpm','/usr/lib64/librpm.so.11','/usr/lib64/librpmio.so.11')}
    admission = dict(schema=1,status='ROOT_REVIEWED_FEDORA44_RPM6_SOURCE_RUNTIME',rpm_nevra='rpm-6.0.2-1.fc44.x86_64',
        source_rpm='rpm-6.0.2-1.fc44.src.rpm',source_rpm_sha256='d'*64,fedora_patchset_sha256='e'*64,
        review_receipt_sha256='f'*64,source_files={p:'d'*64 for p in d.RPM_SOURCE_FILES},runtime=runtime)
    value = dict(schema=1,attempt_nonce='a'*32,case=case,arch='x86_64',source_commit='b'*40,inputs=inputs,
        artifacts=artifacts,accounts={a:dict(name='qsh57'+a,uid=21001+i) for i,a in enumerate(('first','second'))},
        client=dict(sha256=d.digest(b'synthetic-client')),sessions=[dict(stage=stage,account=account,session_nonce=format(i,'032x'))
        for i,(stage,account) in enumerate(d.SESSIONS)] if case=='lifecycle' else [], fault={},expected_initial='pristine',
        output_limit=d.MAX_COMMAND,retained_paths=['/etc/qshd','/etc/qshd/host_key','/var/log/qshd'],
        registry_paths=['/etc/selinux/targeted/contexts/files/file_contexts'],rpm_callback_contract=admission,
        daemon_identity_contract=d.DAEMON_IDENTITY_CONTRACT)
    manifest=root/'manifest.json';manifest.write_bytes(d.canonical(value))
    return d, value, manifest


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(DRIVER.is_file(), 'finite guest driver missing')
        spec = importlib.util.spec_from_file_location('offline_pair_driver', DRIVER)
        self.d = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.d
        spec.loader.exec_module(self.d)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.now = [900000 * 10**9]

    def request(self, sequence=1):
        stage, account = self.d.SESSIONS[sequence - 1]
        return dict(schema=1, attempt_nonce='a' * 32, case='lifecycle', arch='aarch64',
                    sequence=sequence, stage=stage, account=account,
                    session_nonce=hashlib.sha256(str(sequence).encode()).hexdigest()[:32],
                    expected_uid=21001 if account == 'first' else 21002,
                    daemon_fingerprint='SHA256:' + 'A' * 43)

    def result(self, request):
        return dict(request, request_sha256=hashlib.sha256(self.d.canonical(request)).hexdigest(),
                    client_sha256='c' * 64,
                    observations={name: True for name in self.d.OBSERVATION_KEYS}, exit_code=0,
                    pty_eof=True, reaped=True, rescue={name: 0 for name in self.d.RESCUE_KEYS})

    def budget(self, case='lifecycle', marker=None):
        expected = dict(attempt_nonce='a' * 32, case=case, arch='aarch64', manifest_sha256='d' * 64)
        budget = self.d.GuestBudget(expected, marker or self.root / 'attempted', clock_ns=lambda: self.now[0])
        frame = dict(expected, schema=1, type='guest-start', guest_work_budget_ms=1000)
        return budget, frame

    def test_input_identity_and_architecture(self):
        path = self.root / 'opaque'; path.write_bytes(b'not executable')
        descriptor = dict(path=str(path), size=14, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        self.d.verify_input(descriptor)
        for key, value in [('sha256', 'f' * 64), ('size', 1)]:
            bad = dict(descriptor, **{key: value})
            with self.assertRaises(self.d.Refused): self.d.verify_input(bad)
        self.d.validate_architecture('aarch64', 'aarch64')
        with self.assertRaises(self.d.Refused): self.d.validate_architecture('aarch64', 'x86_64')

    def test_hook_inventory_exactly_once(self):
        expected = [('provider', 'A', 'prein', 'one'), ('provider', 'A', 'postin', 'one')]
        records = [dict(role=r, artifact=a, hook=h, count_class=c, executed=True, normal=True,
                        script_sha256='c' * 64, phase_frames=[]) for r, a, h, c in expected]
        self.d.validate_hooks(records, expected)
        for bad in (records[:1], records + [records[0]], list(reversed(records))):
            with self.assertRaises(self.d.Refused): self.d.validate_hooks(bad, expected)
        # Matching RPM6 source uses the raw diagnostic name "post" and a
        # hexadecimal wait status; these are native syntax, not an echoed spec.
        native = (b'D: %post(qshd-selinux-0.5.0-1.fc44.noarch): scriptlet start\n'
                  b'D: %post(qshd-selinux-0.5.0-1.fc44.noarch): execv(/bin/sh) pid 42\n'
                  b'D: %post(qshd-selinux-0.5.0-1.fc44.noarch): waitpid(42) rc 42 status 100\n')
        context = {'qshd-selinux-0.5.0-1.fc44.noarch': dict(role='provider', artifact='A',
            scripts={'postin': 'c' * 64}, interpreter='/bin/sh', flags=0)}
        parsed = self.d.parse_rpm_execution(native, context)
        self.assertEqual((parsed[0]['hook'], parsed[0]['script_exit']), ('postin', 1))
        for bad in (native.replace(b'pid 42', b'pid 43'), native.split(b'D: %post', 2)[0],
                    native.replace(b'scriptlet start', b'echo scriptlet start')):
            with self.assertRaises(self.d.Refused): self.d.parse_rpm_execution(bad, context)

    def test_echoed_script_is_not_execution(self):
        expected = [('provider', 'A', 'prein', 'one')]
        event = dict(role='provider', artifact='A', hook='prein', count_class='one', executed=False,
                     normal=True, script_sha256='c' * 64, phase_frames=[])
        with self.assertRaises(self.d.Refused): self.d.validate_hooks([event], expected)
        event['executed'] = True
        self.d.validate_hooks([event], expected)
        with self.assertRaises(self.d.Refused): self.d.parse_rpm_execution(b'%prein echo scriptlet start\n', {})

    def test_upgrade_preun_is_not_final_erase(self):
        self.d.validate_hooks([dict(role='provider', artifact='A', hook='preun', count_class='positive',
                                   executed=True, normal=True, script_sha256='c' * 64, phase_frames=[])],
                             [('provider', 'A', 'preun', 'positive')])
        with self.assertRaises(self.d.Refused):
            self.d.validate_hooks([dict(role='provider', artifact='A', hook='preun', count_class='zero',
                                       executed=True, normal=True, script_sha256='c' * 64, phase_frames=[])],
                                 [('provider', 'A', 'preun', 'positive')])

    def test_literal_erase_hooks_pin_reviewed_hook_bytes(self):
        hooks = DRIVER.parents[2] / 'packaging/selinux/maintainer'
        self.assertEqual(self.d.LITERAL_ERASE_HOOKS, {
            (role, hook): hashlib.sha256((hooks / (role + '-' + hook)).read_bytes()).hexdigest()
            for role in ('provider', 'consumer') for hook in ('preun', 'postun')})

    def test_old_incoming_roles_are_distinct(self):
        expected = [('provider', 'B', 'prein', 'two-or-more'), ('provider', 'A', 'preun', 'positive')]
        events = [dict(role=r, artifact=a, hook=h, count_class=c, executed=True, normal=True,
                       script_sha256='c' * 64, phase_frames=[]) for r, a, h, c in expected]
        self.d.validate_hooks(events, expected)
        events[0]['artifact'] = 'A'
        with self.assertRaises(self.d.Refused): self.d.validate_hooks(events, expected)

    def test_phase_response_binds_request(self):
        request = dict(schema=2, phase='consumer-post-owned')
        artifact = dict(provider_version='0.3.0', manifest_sha256='a' * 64,
                        core_pp_sha256='b' * 64, contexts_pp_sha256='c' * 64)
        frame = dict(schema=2, phase=request['phase'],
                     request_sha256=hashlib.sha256(self.d.canonical(request).rstrip(b'\n')).hexdigest(),
                     operation_id='d' * 32, artifact=artifact, state='COMPLETE')
        self.d.validate_phase(self.d.canonical(frame), request, artifact)
        for change in ({'request_sha256': '0' * 64}, {'state': 'PENDING'}, {'extra': 1}):
            with self.assertRaises(self.d.Refused):
                self.d.validate_phase(self.d.canonical(dict(frame, **change)), request, artifact)

    def test_both_pair_artifacts_must_change(self):
        a = dict(core_pp_sha256='a' * 64, contexts_pp_sha256='b' * 64)
        b = dict(core_pp_sha256='c' * 64, contexts_pp_sha256='d' * 64)
        self.d.validate_pair_change(a, b)
        for name in a:
            with self.assertRaises(self.d.Refused): self.d.validate_pair_change(a, dict(b, **{name: a[name]}))

    def test_pending_is_not_readiness(self):
        good = dict(state='COMPLETE', expected_pair=['a' * 64, 'b' * 64],
                    current_pair=['a' * 64, 'b' * 64], managed_prestart=True)
        self.d.validate_ready(good)
        for change in ({'state': 'PENDING'}, {'current_pair': ['c' * 64, 'b' * 64]}, {'managed_prestart': False}):
            with self.assertRaises(self.d.Refused): self.d.validate_ready(dict(good, **change))

    def test_pre_refusal_preserves_payload(self):
        before = dict(payload={'binary': 'a' * 64}, pam='b' * 64, private='c' * 64, state='COMPLETE')
        self.d.validate_preserved(before, dict(before, state='PENDING'), ('payload', 'pam', 'private'))
        for key in ('payload', 'pam', 'private'):
            with self.assertRaises(self.d.Refused):
                self.d.validate_preserved(before, dict(before, **{key: 'changed'}), ('payload', 'pam', 'private'))

    def test_acceptance_requires_complete_architecture_matrix(self):
        rows = [dict(arch=a, case=c, result='PASS', nonce=hashlib.sha256((a+c).encode()).hexdigest()[:32])
                for a in self.d.ARCHES for c in self.d.CASES]
        self.d.validate_matrix(rows)
        for bad in ([], rows[:-1], rows + [rows[0]], [r for r in rows if r['arch'] == 'aarch64']):
            with self.assertRaises(self.d.Refused): self.d.validate_matrix(bad)

    def test_rescue_is_not_normal_completion(self):
        good = dict(natural=True, stdout_eof=True, stderr_eof=True, settled=True, unreaped=[],
                    failure=None, group_term_attempts=0, adopted_term_attempts=0, kill_attempts=0, exit_code=1)
        self.d.validate_outcome(good)
        for name, value in [('natural', False), ('stdout_eof', False), ('stderr_eof', False),
                            ('settled', False), ('unreaped', [12]), ('failure', 'TIMEOUT'),
                            ('group_term_attempts', 1), ('adopted_term_attempts', 1), ('kill_attempts', 1)]:
            with self.assertRaises(self.d.Refused): self.d.validate_outcome(dict(good, **{name: value}))

    def test_public_evidence_excludes_private_canary(self):
        private = self.root / 'private'; private.write_bytes(b'PRIVATE_CANARY_57_never_publish')
        record = dict(schema=1, arch='aarch64', case='lifecycle', result='PASS', nonce='a' * 32,
                      hashes={'private': hashlib.sha256(private.read_bytes()).hexdigest()}, count=3,
                      raw=private.read_text(), path=str(private), argv=['private-endpoint'])
        projected = self.d.public_projection(record)
        data = self.d.canonical(projected)
        for value in [private.read_bytes(), str(private).encode(), b'private-endpoint', b'raw', b'argv']:
            self.assertNotIn(value, data)
        self.assertEqual(set(projected), {'schema', 'arch', 'case', 'result', 'nonce', 'hashes', 'count'})
        self.assertEqual(projected['hashes'], {})
        self.assertNotIn(record['hashes']['private'].encode(), data)

    def test_host_pty_request_is_finite_and_bound(self):
        request = self.request()
        self.d.validate_pty_request(self.d.canonical(request), request)
        for change in ({'path': '/tmp/command'}, {'argv': ['sh']}, {'endpoint': 'remote'},
                       {'timeout': 999}, {'stage': 'upgraded-B'}, {'account': 'second'},
                       {'expected_uid': True}, {'daemon_fingerprint': 'SHA256:' + 'B' * 43}, {'sequence': 2}):
            with self.assertRaises(self.d.Refused):
                self.d.validate_pty_request(self.d.canonical(dict(request, **change)), request)
        raw = self.d.canonical(request)
        for malformed in (raw[:-1], raw + b'\n', raw.replace(b'"schema":1', b'"schema":1,"schema":1'), b'x' * 4097):
            with self.assertRaises(self.d.Refused): self.d.validate_pty_request(malformed, request)

    def test_host_pty_result_requires_owned_observations(self):
        request = self.request(); result = self.result(request)
        self.d.validate_pty_result(self.d.canonical(result), request, 'c' * 64)
        variants = [dict(result, request_sha256='0' * 64), dict(result, pty_eof=False),
                    dict(result, reaped=False), dict(result, exit_code=1), dict(result, client_sha256='0' * 64)]
        variants += [dict(result, observations=dict(result['observations'], **{name: False}))
                     for name in self.d.OBSERVATION_KEYS]
        variants += [dict(result, rescue=dict(result['rescue'], **{name: 1})) for name in self.d.RESCUE_KEYS]
        for bad in variants:
            with self.assertRaises(self.d.Refused): self.d.validate_pty_result(self.d.canonical(bad), request, 'c' * 64)

    def test_host_pty_request_cannot_renew_case_deadline(self):
        budget, frame = self.budget(); budget.admit(self.d.canonical(frame))
        original = budget.end_ns; pending = budget.operation_end(120000)
        self.now[0] += 1000000000
        for action in (budget.check, lambda: budget.operation_end(120000), lambda: budget.check(pending)):
            with self.assertRaises(self.d.Refused): action()
        self.assertEqual(budget.end_ns, original)
        with self.assertRaises(self.d.Refused): budget.admit(self.d.canonical(frame))

    def test_host_pty_requires_both_accounts_at_each_stage(self):
        rows = [self.request(i) for i in range(1, 7)]
        self.d.validate_sessions(rows)
        for bad in (rows[:-1], rows + [rows[0]], [rows[1], rows[0]] + rows[2:]):
            with self.assertRaises(self.d.Refused): self.d.validate_sessions(bad)

    def test_deadlines_use_local_clock_domains(self):
        host_now = 1000 * 10**9; host_end = host_now + 200 * 10**9
        grant = self.d.guest_grant_ms('lifecycle', host_end, host_now, 190000)
        self.assertEqual(grant, 10000)
        budget, frame = self.budget(); frame['guest_work_budget_ms'] = grant
        budget.admit(self.d.canonical(frame)); self.assertEqual(budget.end_ns, 900010 * 10**9)
        # Guest clock paused/delayed while authoritative host envelope expired.
        budget.check()
        with self.assertRaises(self.d.Refused): self.d.host_remaining_ms(host_end, host_end)

    def test_guest_budget_admission_is_single_use_and_bounded(self):
        budget, frame = self.budget()
        variants = [dict(frame, **{key: value}) for key, value in [('manifest_sha256', '0'*64),
                    ('attempt_nonce', '0'*32), ('case', 'rpmnew'), ('arch', 'x86_64'),
                    ('guest_work_budget_ms', 0), ('guest_work_budget_ms', -1),
                    ('guest_work_budget_ms', 10800001), ('guest_work_budget_ms', True),
                    ('guest_work_budget_ms', 1.0), ('guest_work_budget_ms', '1')]]
        for bad in variants:
            with self.assertRaises(self.d.Refused): budget.admit(self.d.canonical(bad))
        budget.admit(self.d.canonical(frame))
        restarted, unused = self.budget()
        with self.assertRaises(self.d.Refused): restarted.admit(self.d.canonical(frame))

    def key_fixture(self):
        root = self.root / 'root'; (root / 'etc/qshd').mkdir(parents=True)
        for directory in (root, root / 'etc', root / 'etc/qshd'):
            directory.chmod(0o755)
        key = root / 'etc/qshd/host_key'
        key.write_bytes(b'PRIVATE_CANARY_FIRST_HALF_57_____!'[:32] + bytes(range(32)))
        key.chmod(0o600)
        original_open, original_stat, original_fstat = os.open, os.stat, os.fstat
        def metadata(value, **changes):
            fields = {name: getattr(value, name) for name in dir(value) if name.startswith('st_')}
            return SimpleNamespace(**dict(fields, st_uid=0, st_gid=0, **changes))
        def opened(name, flags, *args, **kwargs):
            return original_open(root if name == '/' else name, flags, *args, **kwargs)
        return root, key, opened, original_stat, original_fstat, metadata

    def test_daemon_observer_reads_only_public_half(self):
        root, key, opened, named, held, metadata = self.key_fixture()
        pread = os.pread
        calls = []
        def read(fd, size, offset):
            calls.append((size, offset)); return pread(fd, size, offset)
        with patch.object(self.d.os, 'open', side_effect=opened), \
             patch.object(self.d.os, 'stat', side_effect=lambda *a, **k: metadata(named(*a, **k))), \
             patch.object(self.d.os, 'fstat', side_effect=lambda *a: metadata(held(*a))), \
             patch.object(self.d.os, 'pread', side_effect=read):
            observed = self.d.observe_daemon_public_key()
        self.assertEqual(calls, [(32, 32)])
        self.assertEqual(observed['public_key_hex'], bytes(range(32)).hex())
        import base64
        expected = 'SHA256:' + base64.b64encode(hashlib.sha256(bytes(range(32))).digest()).decode().rstrip('=')
        self.assertEqual(observed['daemon_fingerprint'], expected)
        self.assertNotIn(b'PRIVATE_CANARY', self.d.canonical(observed))
        self.assertEqual(observed['metadata']['mode'], 0o100600)

    def test_daemon_observer_refuses_metadata_and_aliases(self):
        root, key, opened, named, held, metadata = self.key_fixture()
        key_inode = key.lstat().st_ino
        for field, value in [('st_uid', 1000), ('st_mode', 0o100644), ('st_mode', 0o040600),
                             ('st_nlink', 2), ('st_size', 63)]:
            def changed(st):
                result = metadata(st)
                if stat_is_key(st): setattr(result, field, value)
                return result
            stat_is_key = lambda st: st.st_ino == key_inode
            with patch.object(self.d.os, 'open', side_effect=opened), \
                 patch.object(self.d.os, 'stat', side_effect=lambda *a, **k: changed(named(*a, **k))), \
                 patch.object(self.d.os, 'fstat', side_effect=lambda *a: changed(held(*a))):
                with self.assertRaises(self.d.Refused): self.d.observe_daemon_public_key()
        saved = key.with_name('saved'); key.rename(saved); key.symlink_to(saved)
        with patch.object(self.d.os, 'open', side_effect=opened), \
             patch.object(self.d.os, 'stat', side_effect=lambda *a, **k: metadata(named(*a, **k))), \
             patch.object(self.d.os, 'fstat', side_effect=lambda *a: metadata(held(*a))):
            with self.assertRaises(self.d.Refused): self.d.observe_daemon_public_key()
        key.unlink(); saved.rename(key)
        qshd = root / 'etc/qshd'; saved_dir = root / 'elsewhere'; qshd.rename(saved_dir); qshd.symlink_to(saved_dir)
        with patch.object(self.d.os, 'open', side_effect=opened), \
             patch.object(self.d.os, 'stat', side_effect=lambda *a, **k: metadata(named(*a, **k))), \
             patch.object(self.d.os, 'fstat', side_effect=lambda *a: metadata(held(*a))):
            with self.assertRaises(self.d.Refused): self.d.observe_daemon_public_key()

    def test_daemon_observer_refuses_short_or_changed_reads(self):
        root, key, opened, named, held, metadata = self.key_fixture()
        pread = os.pread
        for kind in ('short', 'replacement', 'mutation'):
            def read(fd, size, offset):
                data = pread(fd, size, offset)
                if kind == 'short': return data[:-1]
                if kind == 'replacement':
                    replacement = key.with_name('replacement'); replacement.write_bytes(b'x' * 64)
                    replacement.chmod(0o600); replacement.replace(key)
                else: os.utime(key, ns=(1, 2))
                return data
            with patch.object(self.d.os, 'open', side_effect=opened), \
                 patch.object(self.d.os, 'stat', side_effect=lambda *a, **k: metadata(named(*a, **k))), \
                 patch.object(self.d.os, 'fstat', side_effect=lambda *a: metadata(held(*a))), \
                 patch.object(self.d.os, 'pread', side_effect=read):
                with self.assertRaises(self.d.Refused): self.d.observe_daemon_public_key()

    def test_daemon_key_absent_before_first_start(self):
        root, key, opened, named, held, metadata = self.key_fixture()
        with patch.object(self.d.os, 'open', side_effect=opened), \
             patch.object(self.d.os, 'stat', side_effect=lambda *a, **k: metadata(named(*a, **k))), \
             patch.object(self.d.os, 'fstat', side_effect=lambda *a: metadata(held(*a))):
            with self.assertRaises(self.d.Refused): self.d.require_daemon_key_absent()
            key.unlink()
            self.assertEqual(self.d.require_daemon_key_absent(), {'schema': 1, 'absent': True})

    def campaign_child(self, command, milliseconds=2000):
        owner = DRIVER.parents[2] / 'packaging/selinux/qshd_selinux_process.py'
        script = self.root / ('worker-' + str(len(list(self.root.iterdir()))) + '.py')
        script.write_text("""import importlib.util,pathlib,resource,sys,json,time
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
d=load('pair_driver',DRIVER_LITERAL);p=load('fixture_primitives',OWNER_LITERAL)
for key,want in [(resource.RLIMIT_CORE,0),(resource.RLIMIT_AS,1024**3),(resource.RLIMIT_CPU,70),(resource.RLIMIT_NOFILE,128),(resource.RLIMIT_FSIZE,16*1024**2)]:resource.setrlimit(key,(want,want))
r=d._campaign_command(p,COMMAND_LITERAL,str(pathlib.Path(__file__).parent),time.monotonic_ns()+BUDGET_LITERAL*1000000)
r.pop('stdout');r.pop('stderr');print(json.dumps(r))
assert p._children()==[]
try:__import__('os').waitpid(-1,__import__('os').WNOHANG)
except ChildProcessError:pass
else:raise AssertionError('unreaped child')
""".replace('DRIVER_LITERAL', repr(str(DRIVER))).replace('OWNER_LITERAL', repr(str(owner))).replace(
            'COMMAND_LITERAL', repr(command)).replace('BUDGET_LITERAL', str(milliseconds)))
        env = dict(os.environ, HOME=str(self.root), XDG_CONFIG_HOME=str(self.root),
                   XDG_CACHE_HOME=str(self.root), TMPDIR=str(self.root), HISTFILE='/dev/null')
        proc = subprocess.run([sys.executable, '-I', '-B', str(script)], env=env,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=20)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def test_campaign_owner_normal_and_nonzero_have_actual_eof_wait(self):
        for code in (0, 7):
            result = self.campaign_child((sys.executable, '-I', '-B', '-c',
                'import sys; print("opaque");sys.stderr.write("bounded\\n");raise SystemExit(' + str(code) + ')'))
            self.d.validate_outcome(result)
            self.assertEqual(result['exit_code'], code)

    def test_campaign_owner_orphan_and_timeout_are_not_success(self):
        orphan = ('import os,signal; p=os.fork(); '
                  'os._exit(0) if p else (os.setsid(),os.close(1),os.close(2),signal.alarm(15),signal.pause())')
        for command in (orphan, 'import time;time.sleep(15)'):
            result = self.campaign_child((sys.executable, '-I', '-B', '-c', command), 300)
            with self.assertRaises(self.d.Refused): self.d.validate_outcome(result)
            self.assertTrue(result['settled']); self.assertEqual(result['unreaped'], [])
            self.assertGreater(sum(result[key] for key in self.d.RESCUE_KEYS), 0)

    def test_campaign_owner_cancellation_and_output_bound_refuse(self):
        result = self.campaign_child((sys.executable, '-I', '-B', '-c', 'import os;os.write(1,b"x"*(1024*1024+1))'))
        with self.assertRaises(self.d.Refused): self.d.validate_outcome(result)
        self.assertEqual(result['failure'], 'CHILD_OUTPUT_LIMIT')
        self.assertTrue(result['settled'])
        result = self.campaign_child((sys.executable, '-I', '-B', '-c', 'import os,signal;os.kill(os.getppid(),signal.SIGINT)'))
        with self.assertRaises(self.d.Refused): self.d.validate_outcome(result)
        self.assertFalse(result['natural']); self.assertTrue(result['settled'])
        result = self.campaign_child((sys.executable, '-I', '-B', '-c',
            'import os,signal,time\nfor i in range(4):\n os.kill(os.getppid(),signal.SIGTERM);time.sleep(.002)\ntime.sleep(15)'))
        with self.assertRaises(self.d.Refused): self.d.validate_outcome(result)
        self.assertTrue(result['settled']);self.assertEqual(result['unreaped'],[])
        self.assertGreaterEqual(result['cancellation_requests'],2)

    def rpm_admission(self):
        runtime = {'/usr/bin/rpm': '1' * 64, '/usr/lib64/librpm.so.10': '2' * 64,
                   '/usr/lib64/librpmio.so.10': '3' * 64}
        value = dict(schema=1, status='ROOT_REVIEWED_FEDORA44_RPM6_SOURCE_RUNTIME',
            rpm_nevra='rpm-6.0.2-1.fc44.x86_64', source_rpm='rpm-6.0.2-1.fc44.src.rpm',
            source_rpm_sha256='4' * 64, fedora_patchset_sha256='5' * 64, review_receipt_sha256='6' * 64,
            source_files={name: '7' * 64 for name in self.d.RPM_SOURCE_FILES}, runtime=runtime)
        return value, runtime

    def branch_fixture(self):
        a = dict(provider_version='0.3.0', manifest_sha256='a' * 64,
                 core_pp_sha256='b' * 64, contexts_pp_sha256='c' * 64)
        b = dict(a, core_pp_sha256='d' * 64, contexts_pp_sha256='e' * 64)
        old = 'qshd-selinux-0.5.0-1.fc44.noarch'
        new = 'qshd-selinux-0.5.0-2.fc44.noarch'
        before = dict(packages={'provider': [old]}, pair=[a['core_pp_sha256'], a['contexts_pp_sha256']])
        after = dict(packages={'provider': [new]}, pair=[b['core_pp_sha256'], b['contexts_pp_sha256']],
                     activation=dict(state='COMPLETE', artifact=b, basis=None))
        records = [dict(role='provider', artifact='A', hook=hook, executed=True, normal=True,
                        script_exit=0, nevra=old, script_sha256=self.d.LITERAL_ERASE_HOOKS[('provider', hook)])
                   for hook in ('preun', 'postun')]
        return {'A': a, 'B': b}, before, after, records

    def test_rpm_runtime_source_admission_is_required(self):
        admission, actual = self.rpm_admission()
        self.d.validate_rpm_admission(admission, actual)
        for bad in (None, {'source_sha256': 'a' * 64}, dict(admission, status='upstream-research'),
                    dict(admission, source_rpm='rpm-unreviewed.src.rpm'),
                    dict(admission, source_files={}), dict(admission, runtime={'/usr/bin/rpm': '1' * 64})):
            with self.assertRaises(self.d.Refused): self.d.validate_rpm_admission(bad, actual)
        with self.assertRaises(self.d.Refused): self.d.validate_rpm_admission(admission, dict(actual, **{'/usr/bin/rpm': '0'*64}))

    def test_old_preun_and_postun_classes_require_complete_capture(self):
        ids, before, after, records = self.branch_fixture(); admission, runtime = self.rpm_admission()
        capture = dict(normal=True, stdout_eof=True, stderr_eof=True)
        value = self.d.classify_rpm_branches(records, [], [], ids, before, after, admission, runtime,
                                            capture=capture, operation='upgrade')
        self.assertEqual([r['count_class'] for r in value], ['positive', 'positive'])
        self.assertEqual(value[0]['count_provenance'], 'exact-literal-branch-elimination')
        self.assertEqual(value[1]['count_provenance'], 'source-backed-same-psm')
        self.assertTrue(all('count' not in r for r in value))
        for bad_capture in (dict(capture, stderr_eof=False), dict(capture, normal=False)):
            with self.assertRaises(self.d.Refused):
                self.d.classify_rpm_branches(records, [], [], ids, before, after, admission, runtime,
                                             capture=bad_capture, operation='upgrade')
        for bad in (records[1:], [dict(records[0], script_exit=1), records[1]],
                    [records[0], dict(records[1], count=1)],
                    [dict(records[0], script_sha256='0'*64), records[1]]):
            with self.assertRaises(self.d.Refused):
                self.d.classify_rpm_branches(bad, [], [], ids, before, after, admission, runtime,
                                             capture=capture, operation='upgrade')

    def test_rpm_direct_phase_classes_are_request_bound_and_unambiguous(self):
        ids, before, after, old = self.branch_fixture(); admission, runtime = self.rpm_admission()
        request = dict(schema=2, phase='provider-pre-owned', artifact=ids['B'])
        value = dict(schema=2, phase=request['phase'], request_sha256=hashlib.sha256(
            self.d.canonical(request).rstrip(b'\n')).hexdigest(), operation_id='f'*32, artifact=ids['B'], state='PENDING')
        event = dict(role='provider', artifact='B', hook='prein', executed=True, normal=True,
                     script_exit=0, nevra='qshd-selinux-0.5.0-2.fc44.noarch', script_sha256='8'*64)
        frames = [(self.d.canonical(value), value)]
        kwargs = dict(capture=dict(normal=True, stdout_eof=True, stderr_eof=True), operation='upgrade')
        result = self.d.classify_rpm_branches([event], frames, [], ids, before, after, admission, runtime, **kwargs)
        self.assertEqual(result[0]['count_class'], 'two-or-more')
        self.assertEqual(result[0]['count_provenance'], 'direct-phase-route')
        for bad in ([], frames + frames, [(self.d.canonical(dict(value, request_sha256='0'*64)), dict(value, request_sha256='0'*64))]):
            with self.assertRaises(self.d.Refused):
                self.d.classify_rpm_branches([event], bad, [], ids, before, after, admission, runtime, **kwargs)

    def test_native_rpm_unknown_alias_pid_interpreter_and_truncation_refuse(self):
        raw = (b'D: %post(qshd-0.5.0-1.fc44.x86_64): scriptlet start\n'
               b'D: %post(qshd-0.5.0-1.fc44.x86_64): execv(/bin/sh) pid 42\n'
               b'D: %post(qshd-0.5.0-1.fc44.x86_64): waitpid(42) rc 42 status 100\n')
        context = {'qshd-0.5.0-1.fc44.x86_64': dict(role='consumer', artifact='A',
                   scripts={'postin':'c'*64}, interpreter='/bin/sh', flags=0)}
        self.assertEqual(self.d.parse_rpm_execution(raw, context)[0]['script_exit'], 1)
        for bad in (raw.replace(b'%post(', b'%postin('), raw.replace(b'/bin/sh', b'/bin/other'),
                    raw.replace(b'waitpid(42)', b'waitpid(43)'), raw.replace(b'rc 42', b'rc 0'),
                    raw[:-1], raw + raw, raw.replace(b'execv(/bin/sh)', b'execv(/bin/sh 2)')):
            with self.assertRaises(self.d.Refused): self.d.parse_rpm_execution(bad, context)

    def test_finite_case_dispatcher_exercises_all_cases_without_repair(self):
        d = self.d; outer = self
        class FakeNative:
            """Synthetic native facts test orchestration, never installed proof."""
            def __init__(self, case, corrupt=False):
                ids, unused, unused2, unused3 = outer.branch_fixture()
                self.m = dict(case=case, artifacts={name: dict(identity=value) for name, value in ids.items()}, fault={})
                if case in ('custom-label', 'default-override'):
                    self.m['fault'] = dict(path='/etc/qshd/host_key', value='system_u:object_r:etc_t:s0'
                        if case == 'custom-label' else 'fixture_admin_t')
                self.p = self.c = None; self.state = None; self.sequence = 0
                self.fault_name = None; self.corrupt = corrupt; self.corrupted = False
                self.pty_results = []; self.actions = []; self.pair_override = None
            def snapshot(self, label):
                identity = self.m['artifacts'][self.p]['identity'] if self.p else None
                label_value = 'system_u:object_r:qshd_etc_t:s0' if self.p else 'system_u:object_r:etc_t:s0'
                default = label_value
                if self.fault_name == 'custom-label': label_value = self.m['fault']['value']
                if self.fault_name == 'default-override': default = 'system_u:object_r:fixture_admin_t:s0'
                metadata = dict(dev=1, ino=2, uid=0, gid=0, mode=0o100600, nlink=1, size=64)
                file = dict(present=True, metadata=metadata, sha256='f'*64, xattrs={}, label=label_value, default_label=default)
                return copy.deepcopy(dict(activation=self.state,
                    pair=self.pair_override if self.pair_override is not None else
                        [identity['core_pp_sha256'], identity['contexts_pp_sha256']] if identity else [None, None],
                    packages=dict(provider=[self.p] if self.p else [], consumer=[self.c] if self.c else []),
                    payload=dict(provider=self.p, consumer=self.c, fault=self.fault_name, corrupt=self.corrupted),
                    retained={'/etc/qshd/host_key':file}, sidecars={}, unrelated_modules='stock',
                    registry={'registry':dict(sha256='a'*64 if self.p is None else 'b'*64,
                                             metadata=dict(uid=0,gid=0,mode=0o100644))},
                    layout={p:dict(present=True,metadata=dict(mode=m,uid=0,gid=0,nlink=1,size=0)) for p,m in
                        [('/var/lib/qshd/selinux-activation',0o040700),('/var/lib/qshd/selinux-activation/lock',0o100600)]}))
            def pristine(self): return self.snapshot('pristine')
            def payload(self, value, provider, consumer):
                outer.assertEqual((self.p,self.c),(provider,consumer))
            def inactive(self, value, **kwargs): pass
            def prepare_accounts(self): self.actions.append(('accounts',))
            def ready(self, artifact):
                outer.assertEqual(self.state['state'],'COMPLETE')
                outer.assertEqual(self.state['artifact'],self.m['artifacts'][artifact]['identity'])
                return self.snapshot('ready')
            def start(self, artifact, **kwargs):
                outer.assertIsNone(self.fault_name, 'faulted case attempted a repair/start')
                self.actions.append(('start',artifact))
            def stop(self): self.actions.append(('stop',));return self.snapshot('stopped')
            def sessions(self, stage):
                for unused in range(2):
                    request=outer.request(len(self.pty_results)+1)
                    outer.assertEqual(request['stage'],stage)
                    self.pty_results.append(outer.result(request))
            def transaction(self, kind, artifact, roles, **options):
                self.actions.append((kind,artifact,tuple(roles),options))
                if options.get('refuse'):
                    if self.corrupt:self.corrupted=True
                    return self.snapshot('refused')
                outer.assertIsNone(self.fault_name, 'faulted case mutated packages instead of refusing')
                self.sequence+=1
                for role in roles:
                    if role=='provider':self.p=None if kind=='erase' else artifact
                    else:self.c=None if kind=='erase' else artifact
                if self.p is None:self.state=None
                else:
                    identity=self.m['artifacts'][self.p]['identity']
                    pending=kind=='erase' or options.get('skip_post')
                    basis=self.m['artifacts'][options.get('installed',self.p)]['identity']
                    self.state=dict(state='PENDING' if pending else 'COMPLETE',artifact=identity,
                        basis=dict(artifact=basis) if pending else None,
                        completion=None if pending else {},operation_id=format(self.sequence,'032x'))
                if options.get('skip_post'):
                    old=self.m['artifacts']['A']['identity'];self.pair_override=[old['core_pp_sha256'],old['contexts_pp_sha256']]
                return self.snapshot('transaction')
            def staged(self, hook, count, **kwargs):
                self.actions.append(('staged',hook,count,kwargs))
                if hook=='prein' and not kwargs.get('refuse'):
                    self.state=dict(state='PENDING',artifact=self.m['artifacts']['B']['identity'],
                        basis=dict(artifact=self.m['artifacts']['A']['identity']),completion=None,operation_id='1'*32)
            def fault(self, case):
                self.fault_name=case;self.actions.append(('fault',case))
                a=self.m['artifacts']['A']['identity'];b=self.m['artifacts']['B']['identity']
                if case in ('missing-pair','partial-erase'):self.pair_override=[a['core_pp_sha256'],None]
                if case=='mixed-pair':self.pair_override=[b['core_pp_sha256'],a['contexts_pp_sha256']]
                if case=='loaded-new-pending':self.pair_override=[b['core_pp_sha256'],b['contexts_pp_sha256']]
            def gate_refuses(self):self.actions.append(('gate-refuses',))
            def refused_start(self):self.actions.append(('refused-start',))
        for case in d.CASES:
            with self.subTest(case=case):
                native=FakeNative(case);d.CaseDriver(native).run()
                if case=='lifecycle':
                    outer.assertEqual(len(native.pty_results),6)
                    upgrades=[row[2] for row in native.actions if row[0]=='upgrade']
                    outer.assertEqual(upgrades,[('provider',),('consumer',)])
                elif case=='preowned-transfer':
                    outer.assertTrue(any(row[:3]==('staged','prein',2) for row in native.actions))
                else:
                    outer.assertTrue(any(row[0]=='fault' for row in native.actions))
        with self.assertRaises(d.Refused): d.CaseDriver(FakeNative('missing-pair',corrupt=True)).run()

    def test_import_and_cli_without_manifest_never_run_native_operations(self):
        for arguments, expected in ((['--help'],0),([],2)):
            proc=subprocess.run([sys.executable,'-I','-B',str(DRIVER),*arguments],capture_output=True,timeout=5,
                env=dict(os.environ,HOME=str(self.root),XDG_CONFIG_HOME=str(self.root),XDG_CACHE_HOME=str(self.root),HISTFILE='/dev/null'))
            self.assertEqual(proc.returncode,expected,proc.stderr)

    def test_failed_managed_start_cancels_retry_before_slow_snapshot(self):
        native = object.__new__(self.d.Native)
        actions = []; stopped = [False]
        service = dict(ActiveState='inactive', process=None, listeners=[], cgroup_pids=[],
                       ExecStartPre='code=exited ; status=1', ExecMainStartTimestampMonotonic='10')
        state = dict(state='COMPLETE', operation_id='historical-only')
        def snapshot(label):
            if label != 'before-refused-managed-start':
                self.assertTrue(stopped[0], 'slow metadata allowed scheduled Restart before stop')
            return dict(service=copy.deepcopy(service), activation=copy.deepcopy(state))
        def run(argv, **kwargs):
            actions.append(tuple(argv))
            if argv[1] == 'stop':stopped[0] = True
            return (1 if argv[1] == 'start' else 0), b'', b''
        native.snapshot=snapshot;native.run=run;native.event=lambda *a,**k:None
        native.refused_start()
        self.assertEqual([argv[1] for argv in actions], ['start','stop'])


    def test_actual_manifest_admission_all_fourteen_case_session_inventories(self):
        for case in self.d.CASES:
            with self.subTest(case=case):
                d, value, manifest = rooted_manifest_fixture(self.root/case, case)
                self.assertEqual(d.load_manifest(manifest,case)[1]['sessions'], value['sessions'])
                variants = [value['sessions'][:5], list(reversed(value['sessions'])), value['sessions'][:1]*6] if case=='lifecycle' else [[dict(stage='initial-A',account='first',session_nonce='a'*32)]]
                for slots in variants:
                    manifest.write_bytes(d.canonical(dict(value,sessions=slots)))
                    with self.assertRaises(d.Refused):d.load_manifest(manifest,case)

    def test_actual_drain_transient_busy_then_finished_uses_original_end(self):
        d=self.d; native=object.__new__(d.Native); now=[0]; deadlines=[]; events=[]
        native.budget=SimpleNamespace(operation_end=lambda milliseconds:60000000000)
        keys=('admitted','provisional','retiring','retiring_pending','charged','unconfirmed','missing_monitor','wait_lost',
              'monitor_failed','receipt_lost','retired_slots','wait_outstanding','receipt_outstanding')
        def frame(pam,busy=0,**extra):
            counts=dict.fromkeys(keys,0);counts.update(charged=busy,pam=pam,cleanup_failure=None);counts.update(extra)
            return dict(schema=2,phase='serving',capacity='available',limit=64,counts=counts)
        finished=dict(state='finished',close_session='ok',delete_cred='ok',end='ok')
        def exercise(values,advance=1000000000):
            now[0]=0;queue=list(values);events.clear();deadlines.clear()
            def run(argv,seconds):
                deadlines.append(seconds);now[0]+=advance
                return 0,d.canonical(queue.pop(0) if len(queue)>1 else queue[0]),b''
            native.run=run;native.event=lambda *a,**k:events.append((a,k))
            with patch.object(d.time,'monotonic_ns',side_effect=lambda:now[0]),patch.object(d.time,'sleep',return_value=None):native.drain()
        exercise([frame(dict(state='not_opened'),1),frame(finished)])
        self.assertEqual(len(deadlines),2);self.assertEqual(len(events),1)
        for value in (frame(dict(state='not_opened')),frame(dict(state='unknown'),1),
                      frame(dict(finished,end='failed')),frame(dict(finished,delete_cred='skipped')),
                      frame(finished,1,wait_lost=1),frame(finished,1,cleanup_failure={'operation':'pty_label_restore','errno':1})):
            with self.subTest(value=value),self.assertRaises(d.Refused):exercise([value])
        for values in ([frame(dict(state='not_opened'),1)], [frame(finished)]):
            with self.assertRaises(d.Refused):exercise(values,advance=60000000000)


def load_tests(loader, tests, pattern):
    suite = loader.loadTestsFromTestCase(AcceptanceTests)
    if suite.countTestCases() != 35:
        raise AssertionError('required offline acceptance case count drift')
    return suite


if __name__ == '__main__':
    result = unittest.main(exit=False).result
    raise SystemExit(0 if result.wasSuccessful() and result.testsRun == 35 and not result.skipped else 1)
