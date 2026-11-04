"""Execute Fedora hook assets against owned endpoints; never touch host services."""
import hashlib
import importlib.util
import io
import json
import os
from dataclasses import asdict, replace
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / 'packaging/selinux'
HOOKS = SOURCE / 'maintainer'
PHASE_PATH = '/usr/libexec/qshd-selinux/qshd_selinux_phase.py'
TRUST = dict(provider_version='0.3.0', manifest_sha256='a' * 64,
             core_pp_sha256='b' * 64, contexts_pp_sha256='c' * 64)
INCOMING = json.dumps(TRUST, sort_keys=True, separators=(',', ':'))
NAMES = ('provider-pre', 'provider-post', 'provider-preun', 'provider-postun',
         'consumer-pre', 'consumer-post', 'consumer-preun', 'consumer-postun')


class HookTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / 'events'
        self.manager = self.root / 'systemd'
        self.manager.mkdir()
        self.endpoint = self.root / 'phase.py'
        self.endpoint.write_text('''import json, os, pathlib, sys

def event(value):
    with open(os.environ['QSH_TEST_EVENTS'], 'a') as output:
        output.write(json.dumps(value) + '\\n')
event(['phase', *sys.argv[1:]])
if os.environ.get('QSH_TEST_PHASE_FAIL'):
    raise SystemExit(19)
if os.environ.get('QSH_TEST_ELIGIBILITY'):
    sys.path.insert(0, ''' + repr(str(ROOT)) + ''')
    from scripts.tests.test_selinux_consumer_activation import Bindings
    import qshd_selinux_consumer_activation as consumer
    scenario = os.environ['QSH_TEST_ELIGIBILITY']
    directory = pathlib.Path(os.environ['QSH_TEST_STATE'])
    directory.mkdir(mode=0o700)
    binding = Bindings(directory)
    if scenario != 'fresh-absent':
        binding.installed_files()
        pam = directory / 'etc/pam.d/qshd'
        if scenario == 'absent': pam.unlink()
        elif scenario == 'custom': pam.write_bytes(b'unsupported administrator PAM\\n')
        elif scenario == 'legacy-pam': pam.write_bytes(pathlib.Path(''' + repr(str(ROOT / 'packaging/pam.d/qshd.fedora')) + ''').read_bytes())
        elif scenario in ('rpmnew', 'rpmsave'):
            (directory / ('etc/pam.d/qshd.' + scenario)).write_bytes(b'unclaimed sidecar\\n')
        elif scenario == 'legacy-state':
            slot = binding.common / 'selinux-activation/activation.json'
            value = json.loads(slot.read_bytes()); value['schema'] = 1
            slot.write_text(json.dumps(value, sort_keys=True, separators=(',', ':')))
    try:
        result = consumer._Coordinator(binding, clock=lambda: binding.now).invalidate_installed_consumer_pre(
            fresh=sys.argv[1] == 'consumer-pre-fresh', deadline=1000)
    except consumer.CoordinatorError:
        event(['eligibility-refused'])
        raise SystemExit(23)
    assert result.state == 'PENDING'
    assert not binding.active
    event(['eligible'])
''')
        self.commands = {}
        for name in ('getent', 'useradd', 'systemctl'):
            path = self.root / name
            path.write_text('#!' + sys.executable + '\n' + '''import json, os, sys
with open(os.environ['QSH_TEST_EVENTS'], 'a') as output:
    output.write(json.dumps([''' + repr(name) + ''', *sys.argv[1:]]) + '\\n')
raise SystemExit(int(os.environ.get('QSH_TEST_''' + name.upper() + '''_STATUS', '0')))
''')
            path.chmod(0o755)
            self.commands[name] = path
        self.environment = dict(os.environ, HOME=str(self.root),
                                XDG_CONFIG_HOME=str(self.root / 'config'),
                                XDG_CACHE_HOME=str(self.root / 'cache'),
                                TMPDIR=str(self.root), HISTFILE='/dev/null',
                                PYTHONDONTWRITEBYTECODE='1', QSH_TEST_EVENTS=str(self.log))
        self.capsule = ("import json,os\nwith open(os.environ['QSH_TEST_EVENTS'],'a') as output: "
                        "output.write(json.dumps(['capsule'])+'\\n')")

    def events(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def run_hook(self, name, arguments, *, env=None, capsule=None, incoming=INCOMING):
        source = HOOKS / name
        self.assertTrue(source.is_file(), 'missing Fedora hook ' + name)
        text = source.read_text()
        # Substitute only external boundaries in a copy of the real hook bytes.
        # Shell routing, count validation, ordering and error handling stay intact.
        text = text.replace('/usr/bin/python3', shlex.quote(sys.executable))
        text = text.replace(PHASE_PATH, str(self.endpoint))
        for tool, absolute in [('getent', '/usr/bin/getent'), ('useradd', '/usr/sbin/useradd'),
                               ('systemctl', '/usr/bin/systemctl')]:
            text = text.replace(absolute, str(self.commands[tool]))
        text = text.replace('/run/systemd/system', str(self.manager))
        text = text.replace('@QSHD_PROVIDER_PRE_CAPSULE@', self.capsule if capsule is None else capsule)
        text = text.replace('@QSHD_INCOMING_ARTIFACT_JSON@', incoming)
        script = self.root / ('run-' + name)
        script.write_text(text)
        environment = dict(self.environment, **({} if env is None else env))
        return subprocess.run(['/bin/sh', str(script), *arguments], env=environment,
                              cwd=self.root, capture_output=True, timeout=20)

    def test_count_table_routes_only_selected_phase(self):
        routes = {
            'provider-pre': ('capsule', 'provider-pre-owned', None),
            'provider-post': ('provider-post-pristine', 'provider-post-owned', None),
            'provider-preun': (None, None, 'provider-preun-final'),
            'provider-postun': (None, None, None),
            'consumer-pre': ('consumer-pre-fresh', 'consumer-pre-installed', None),
            'consumer-post': ('consumer-post-owned', 'consumer-post-owned', None),
            'consumer-preun': (None, None, 'consumer-preun-final'),
            'consumer-postun': (None, None, None),
        }
        for name in NAMES:
            for count in ('1', '2', '17', '999999999999999999999999', '0'):
                with self.subTest(hook=name, count=count):
                    self.log.unlink(missing_ok=True)
                    result = self.run_hook(name, [count])
                    route = routes[name][2 if count == '0' else 0 if count == '1' else 1]
                    invalid = count == '0' and name in ('provider-pre', 'provider-post', 'consumer-pre', 'consumer-post')
                    self.assertEqual(result.returncode == 0, not invalid, result.stderr)
                    calls = [event for event in self.events() if event[0] in ('phase', 'capsule')]
                    expected = [] if route is None else [['capsule']] if route == 'capsule' else [['phase', route] + ([INCOMING] if route == 'provider-pre-owned' else [])]
                    self.assertEqual(calls, expected)
                    if invalid: self.assertEqual(self.events(), [])

    def test_missing_malformed_and_extra_counts_refuse_without_actions(self):
        for name in NAMES:
            for arguments in ([], [''], ['-1'], ['01'], ['00'], ['+1'], ['1.0'], [' 1'], ['1 '], ['upgrade'], ['1\n'], ['1', '2']):
                with self.subTest(hook=name, arguments=arguments):
                    self.log.unlink(missing_ok=True)
                    result = self.run_hook(name, arguments)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(self.events(), [])

    def test_required_helper_failures_propagate_without_reload(self):
        for name, count in (('provider-pre', '2'), ('provider-post', '1'), ('provider-post', '2'),
                            ('provider-preun', '0'), ('consumer-pre', '1'), ('consumer-pre', '2'),
                            ('consumer-post', '1'), ('consumer-preun', '0')):
            with self.subTest(hook=name, count=count):
                self.log.unlink(missing_ok=True)
                result = self.run_hook(name, [count], env={'QSH_TEST_PHASE_FAIL': 'yes'})
                self.assertEqual(result.returncode, 19, result.stderr)
                self.assertFalse(any(event[0] == 'systemctl' for event in self.events()))
        self.log.unlink(missing_ok=True)
        result = self.run_hook('provider-pre', ['1'], capsule='raise SystemExit(31)')
        self.assertEqual(result.returncode, 31)
        self.assertEqual(self.events(), [])

    def test_consumer_post_creates_account_then_proves_readiness_then_reloads(self):
        result = self.run_hook('consumer-post', ['1'], env={'QSH_TEST_GETENT_STATUS': '2'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events(), [
            ['getent', 'passwd', 'qshd'],
            ['useradd', '--system', '--no-create-home', '--home-dir', '/nonexistent',
             '--shell', '/usr/sbin/nologin', '--comment', 'qshd worker', 'qshd'],
            ['phase', 'consumer-post-owned'], ['systemctl', '--system', 'daemon-reload']])
        self.log.unlink()
        result = self.run_hook('consumer-post', ['2'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events(), [['getent', 'passwd', 'qshd'],
                                        ['phase', 'consumer-post-owned'],
                                        ['systemctl', '--system', 'daemon-reload']])
        self.log.unlink()
        result = self.run_hook('consumer-post', ['2'], env={'QSH_TEST_GETENT_STATUS': '2', 'QSH_TEST_USERADD_STATUS': '27'})
        self.assertEqual(result.returncode, 27)
        self.assertFalse(any(event[0] in ('phase', 'systemctl') for event in self.events()))

    def test_reload_is_optional_and_hooks_never_activate_or_stop_service(self):
        for name in NAMES:
            for count in ('1', '2', '0'):
                with self.subTest(hook=name, count=count):
                    self.log.unlink(missing_ok=True)
                    result = self.run_hook(name, [count], env={'QSH_TEST_SYSTEMCTL_STATUS': '7'})
                    if not (count == '0' and name in ('provider-pre', 'provider-post', 'consumer-pre', 'consumer-post')):
                        self.assertEqual(result.returncode, 0, result.stderr)
                    for event in self.events():
                        if event[0] == 'systemctl':
                            self.assertEqual(event, ['systemctl', '--system', 'daemon-reload'])
        self.manager.rmdir()
        self.log.unlink(missing_ok=True)
        result = self.run_hook('consumer-postun', ['0'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events(), [])

    def test_fresh_provider_capsule_does_not_need_installed_phase_or_fallback(self):
        self.endpoint.unlink()
        result = self.run_hook('provider-pre', ['1'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events(), [['capsule']])
        self.log.unlink()
        result = self.run_hook('provider-pre', ['2'])
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.events(), [])

    def test_actual_reviewed_capsule_runs_without_installed_imports(self):
        # Use the maintained eight-module renderer. The only synthetic body is
        # the native/state boundary, as in the standalone capsule controls.
        sys.path.insert(0, str(SOURCE))
        import embed_provider_pre as embed
        import qshd_selinux_activation as model
        sources = {name: (SOURCE / (name + '.py')).read_bytes() for name in embed.MODULES}
        sources['qshd_selinux_provider_pre'] += b"\nos.geteuid=lambda:0\ndef invalidate_fresh_provider_pre(trusted_artifact,*,deadline):\n    return model.Activation(2,'PENDING','a'*32,'fedora44-targeted-pair-v2',2,1,trusted_artifact,model.ModulePair(model.ModuleIdentity('qshd',400,'targeted','pp'),model.ModuleIdentity('qshd_contexts',400,'targeted','pp')),'provider-fresh',None,None)\n"
        artifact = (SOURCE / 'artifact.json').read_bytes()
        core = b'explicit synthetic core PP, never loaded'
        contexts = b'explicit synthetic contexts PP, never loaded'
        trusted = model.TrustedArtifact('0.3.0', hashlib.sha256(artifact).hexdigest(),
                                       hashlib.sha256(core).hexdigest(), hashlib.sha256(contexts).hexdigest())
        capsule = embed.render(sources, trusted, artifact_bytes=artifact,
                               core_pp_bytes=core, contexts_pp_bytes=contexts)
        incoming = json.dumps(asdict(trusted), sort_keys=True, separators=(',', ':'))
        self.endpoint.unlink()
        (self.root / 'qshd_selinux_activation.py').write_text("raise AssertionError('filesystem import')")
        result = self.run_hook('provider-pre', ['1'], capsule=capsule.decode(), incoming=incoming)
        self.assertEqual(result.returncode, 0, result.stderr)
        frame = json.loads(result.stdout)
        self.assertEqual(frame['phase'], 'provider-pre-fresh')
        self.assertEqual(frame['state'], 'PENDING')
        self.assertEqual(frame['request_sha256'], hashlib.sha256(embed._request(trusted)).hexdigest())
        self.assertEqual(self.events(), [])

    def test_consumer_eligibility_precedes_payload_and_never_falls_back(self):
        for scenario, count, accepted in (('fresh-absent', '1', True), ('canonical', '2', True),
                                          ('absent', '2', False), ('custom', '2', False),
                                          ('legacy-pam', '2', False), ('rpmnew', '2', False),
                                          ('rpmsave', '2', False), ('legacy-state', '2', False)):
            with self.subTest(scenario=scenario):
                self.log.unlink(missing_ok=True)
                state = self.root / ('state-' + scenario)
                result = self.run_hook('consumer-pre', [count], env={
                    'QSH_TEST_ELIGIBILITY': scenario, 'QSH_TEST_STATE': str(state)})
                marker = self.root / ('payload-' + scenario)
                if result.returncode == 0: marker.write_text('simulated RPM payload replacement')
                self.assertEqual(result.returncode, 0 if accepted else 23, result.stderr)
                self.assertEqual(marker.exists(), accepted)
                self.assertEqual(self.events(), [['phase', 'consumer-pre-fresh' if count == '1' else 'consumer-pre-installed'],
                                                ['eligible' if accepted else 'eligibility-refused']])
                if not accepted:
                    self.assertFalse(any(event[0] in ('capsule', 'systemctl') for event in self.events()))


class UnitTests(unittest.TestCase):
    def test_dedicated_unit_preserves_runtime_contract_and_adds_bounded_gate(self):
        unit = SOURCE / 'qshd-fedora-system.service'
        self.assertTrue(unit.is_file(), 'missing dedicated Fedora system unit')
        def settings(path):
            return dict(line.split('=', 1) for line in path.read_text().splitlines()
                        if '=' in line and not line.startswith(('#', ';')))
        actual = settings(unit)
        generic = settings(ROOT / 'packaging/qshd-system.service')
        self.assertEqual(actual['ExecStartPre'], '/usr/bin/python3 -I -B ' + PHASE_PATH + ' managed-prestart')
        self.assertEqual(actual['TimeoutStartSec'], '460s')
        for name in ('ExecStart', 'RuntimeDirectory', 'RuntimeDirectoryMode', 'KillMode', 'Restart', 'RestartSec'):
            self.assertEqual(actual[name], generic[name])



class ManagedPrestartTests(unittest.TestCase):
    def setUp(self):
        if str(SOURCE) not in sys.path: sys.path.insert(0, str(SOURCE))
        spec = importlib.util.spec_from_file_location('fedora_phase_under_test', SOURCE / 'qshd_selinux_phase.py')
        self.phase = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.phase)
        self.assertIn('managed-prestart', self.phase._PHASES, 'fixed managed route missing')

    def record(self):
        from qshd_selinux_activation import ContextBinding
        from qshd_selinux_observer import ManagedPrestartObservation
        return ManagedPrestartObservation('fedora44-targeted-pair-v2', ContextBinding('d' * 64, 'e' * 64))

    def frame(self):
        request = b'{"phase":"managed-prestart","schema":2}'
        return request, dict(schema=2, phase='managed-prestart', profile='fedora44-targeted-pair-v2',
                             request_sha256=hashlib.sha256(request).hexdigest(),
                             registry_sha256='d' * 64, receipts_sha256='e' * 64)

    @staticmethod
    def canonical(value):
        return json.dumps(value, sort_keys=True, separators=(',', ':')).encode('ascii') + b'\n'

    def test_fixed_request_and_typed_canonical_six_field_response(self):
        request, frame = self.frame()
        self.assertEqual(self.phase._request('managed-prestart'), request)
        self.assertEqual(self.phase._parse_request(request), {'schema': 2, 'phase': 'managed-prestart'})
        self.assertEqual(self.phase._response(self.record(), request), self.canonical(frame))
        self.assertEqual(self.phase._parse_response(self.canonical(frame), request), frame)
        self.assertEqual(set(frame), {'schema', 'phase', 'request_sha256', 'profile', 'registry_sha256', 'receipts_sha256'})

    def test_malformed_extra_stale_and_cross_type_frames_refuse(self):
        request, frame = self.frame()
        other = self.phase._request('consumer-pre-fresh')
        wrong = [self.canonical(frame) + b'\n', self.canonical(frame) * 2,
                 json.dumps(frame).encode() + b'\n', b'x' * 4097,
                 self.canonical(frame).replace(b'"schema":2', b'"schema":2,"schema":2')]
        for change in ({'schema': True}, {'phase': 'consumer-pre-fresh'}, {'profile': 'fedora44-targeted-v1'},
                       {'profile': True}, {'registry_sha256': 'invalid'}, {'receipts_sha256': False},
                       {'request_sha256': hashlib.sha256(other).hexdigest()}, {'operation_id': 'c' * 32},
                       {'state': 'COMPLETE'}, {'result': 'ERASED'}, {'artifact': TRUST}):
            wrong.append(self.canonical(dict(frame, **change)))
        for missing in frame:
            wrong.append(self.canonical({key: value for key, value in frame.items() if key != missing}))
        for value in wrong:
            with self.subTest(value=value[:80]), self.assertRaises(self.phase.PhaseError):
                self.phase._parse_response(value, request)
        with self.assertRaises(self.phase.PhaseError): self.phase._parse_response(self.canonical(frame), other)
        with self.assertRaises(self.phase.PhaseError): self.phase._request('managed-prestart', object())
        with self.assertRaises(self.phase.PhaseError): self.phase._parse_request(request[:-1] + b',"deadline":999}')

    def test_actual_activation_erasure_and_duck_types_cannot_be_managed_results(self):
        from qshd_selinux_activation import ContextBinding, TrustedArtifact, Completion, PairDigests
        from qshd_selinux_first_activation import _pending
        from qshd_selinux_observer import ManagedPrestartObservation
        from qshd_selinux_provider_erase import ErasureResult
        request, _ = self.frame()
        trust = TrustedArtifact(**TRUST)
        pending = _pending(trust, 'provider-fresh')
        complete = replace(pending, state='COMPLETE', completion=Completion('normal-pair-install-reload-v2',
                           PairDigests(trust.core_pp_sha256, trust.contexts_pp_sha256), self.record().contexts))
        erased = ErasureResult('a' * 32, trust)
        forged = ContextBinding('d' * 64, 'e' * 64)
        object.__setattr__(forged, 'registry_sha256', 'invalid')
        records = [pending, complete, erased, object(), SimpleNamespace(profile='fedora44-targeted-pair-v2', contexts=self.record().contexts),
                   ManagedPrestartObservation('fedora44-targeted-v1', self.record().contexts),
                   ManagedPrestartObservation('fedora44-targeted-pair-v2', SimpleNamespace(registry_sha256='d' * 64, receipts_sha256='e' * 64)),
                   ManagedPrestartObservation('fedora44-targeted-pair-v2', forged)]
        for record in records:
            with self.subTest(record=type(record)), self.assertRaises(self.phase.PhaseError):
                self.phase._response(record, request)
        for phase, record in [('provider-post-pristine', complete), ('provider-preun-final', erased)]:
            other = self.phase._request(phase)
            with self.assertRaises(self.phase.PhaseError): self.phase._response(self.record(), other)
            raw = self.phase._response(record, other)
            with self.assertRaises(self.phase.PhaseError): self.phase._parse_response(raw, request)

    def test_dispatch_calls_only_installed_observer_with_original_deadline(self):
        import qshd_selinux_observer as observer
        import qshd_selinux_package_state as package
        import qshd_selinux_consumer_activation as consumer
        deadline = object()
        observed = self.record()
        calls = []
        def observe(**kwargs):
            calls.append(kwargs)
            return observed
        with patch.object(observer, 'observe_installed_managed_prestart', side_effect=observe), \
             patch.object(package, 'production', side_effect=AssertionError('no outer package lease')), \
             patch.object(consumer._Production, 'guard', side_effect=AssertionError('no maintenance guard')):
            self.assertIs(self.phase._dispatch('managed-prestart', deadline=deadline), observed)
        self.assertEqual(len(calls), 1)
        self.assertEqual(set(calls[0]), {'deadline'})
        self.assertIs(calls[0]['deadline'], deadline)

    def test_child_passes_original_work_end_and_refuses_expiry_without_dispatch(self):
        import qshd_selinux_observer as observer
        request, frame = self.frame()
        output = SimpleNamespace(buffer=io.BytesIO())
        calls = []
        def observe(*, deadline):
            calls.append(deadline)
            return self.record()
        with patch.object(self.phase, '_resources'), patch.object(self.phase.time, 'monotonic', return_value=101), \
             patch.object(observer, 'observe_installed_managed_prestart', side_effect=observe), \
             patch.object(self.phase.sys, 'stdout', output):
            self.assertEqual(self.phase._child_main([request.decode(), '100', '530']), 0)
        self.assertEqual(calls, [530])
        self.assertEqual(output.buffer.getvalue(), self.canonical(frame))
        with patch.object(self.phase, '_resources', side_effect=AssertionError('expired before admission')), \
             patch.object(self.phase.time, 'monotonic', return_value=531), \
             patch.object(observer, 'observe_installed_managed_prestart', side_effect=AssertionError('expired before observation')):
            with self.assertRaises(self.phase.PhaseError): self.phase._child_main([request.decode(), '100', '530'])

    def test_delivered_twenty_three_module_loader_dispatches_managed_observation(self):
        spec = importlib.util.spec_from_file_location('fedora_payload_builder', SOURCE / 'assemble_payload.py')
        builder = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(builder)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            core = root / 'qshd.pp'
            core.write_bytes(b'explicit inert core PP; never loaded')
            contexts = root / 'qshd_contexts.pp'
            contexts.write_bytes(b'explicit inert contexts PP; never loaded')
            artifact = SOURCE / 'artifact.json'
            pam = ROOT / 'packaging/pam.d/qshd.fedora-selinux'
            expected = {name: hashlib.sha256((SOURCE / name).read_bytes()).hexdigest() for name in builder.MODULES}
            expected.update({path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (core, contexts, artifact, pam)})
            output = root / 'payload'
            inventory = builder.assemble_payload(SOURCE, core, contexts, artifact, pam, expected, output, 1000000000)
            self.assertEqual(len(builder.MODULES), 23)
            self.assertEqual(len(expected), 27)
            self.assertEqual(len(inventory), 28)
            installed = output / 'usr/libexec/qshd-selinux'
            poison = root / 'poison'
            poison.mkdir()
            (poison / 'qshd_selinux_observer.py').write_text("raise AssertionError('filesystem fallback')")
            program = """import importlib.util,pathlib,sys
from unittest.mock import patch
root=pathlib.Path(sys.argv[1])
spec=importlib.util.spec_from_file_location('qshd_selinux_phase',root/'qshd_selinux_phase.py')
phase=importlib.util.module_from_spec(spec);sys.modules[spec.name]=phase;spec.loader.exec_module(phase)
before=list(sys.path);phase._install_loader();assert sys.path==before
import qshd_selinux_observer as observer
import qshd_selinux_package_state as package
from qshd_selinux_activation import ContextBinding
assert pathlib.Path(observer.__file__).parent==root
record=observer.ManagedPrestartObservation('fedora44-targeted-pair-v2',ContextBinding('d'*64,'e'*64))
calls=[]
def observe(*,deadline):calls.append(deadline);return record
with patch.object(observer,'observe_installed_managed_prestart',side_effect=observe),patch.object(package,'production',side_effect=AssertionError('outer package lease')):
    result=phase._dispatch('managed-prestart',deadline=1234.0)
assert result is record and calls==[1234.0]
request=phase._request('managed-prestart');frame=phase._response(result,request)
phase._parse_response(frame,request)
for name in phase._MODULES:
    if name in sys.modules:assert pathlib.Path(sys.modules[name].__file__).parent==root
assert str(root) not in sys.path
sys.stdout.buffer.write(frame)
"""
            environment = dict(os.environ, HOME=directory, XDG_CACHE_HOME=directory,
                               XDG_CONFIG_HOME=directory, TMPDIR=directory, HISTFILE='/dev/null',
                               PYTHONDONTWRITEBYTECODE='1', PYTHONPATH=str(poison))
            result = subprocess.run([sys.executable, '-I', '-B', '-c', program, str(installed)],
                                    cwd=poison, env=environment, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, b'')
            _, frame = self.frame()
            self.assertEqual(result.stdout, self.canonical(frame))

    def test_actual_public_managed_cli_refuses_extra_or_parameterized_requests(self):
        with tempfile.TemporaryDirectory() as directory:
            environment = dict(os.environ, HOME=directory, XDG_CACHE_HOME=directory,
                               XDG_CONFIG_HOME=directory, TMPDIR=directory, HISTFILE='/dev/null',
                               PYTHONDONTWRITEBYTECODE='1')
            for arguments in (['managed-prestart', 'extra'], ['managed-prestart', '--deadline', '999'],
                              ['managed-prestart '], ['managed-prestart --deadline 999']):
                with self.subTest(arguments=arguments):
                    result = subprocess.run([sys.executable, '-I', '-B', str(SOURCE / 'qshd_selinux_phase.py'), *arguments],
                                            cwd=directory, env=environment, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertEqual(result.stdout, b'')
                    self.assertEqual(result.stderr, b'PHASE_REFUSED\n')

    def test_actual_owned_child_forwards_only_bound_managed_frame(self):
        program = """import importlib.util,json,os,pathlib,resource,sys,time
root=pathlib.Path(SOURCE_LITERAL);sys.path.insert(0,str(root))
for key,value in ((resource.RLIMIT_CORE,0),(resource.RLIMIT_FSIZE,16*1024**2),(resource.RLIMIT_AS,1024**3),(resource.RLIMIT_CPU,15)):
    resource.setrlimit(key,(value,value))
spec=importlib.util.spec_from_file_location('actual_managed_phase',root/'qshd_selinux_phase.py')
phase=importlib.util.module_from_spec(spec);sys.modules[spec.name]=phase;spec.loader.exec_module(phase)
# Substitute root resource admission and observation only. The owned process,
# child deadline/parser, typed result, pipes, EOF and waits remain production.
phase._resources=lambda **kwargs:None
if len(sys.argv)>1:
    assert sys.argv[1]==phase._CHILD
    from qshd_selinux_activation import ContextBinding
    from qshd_selinux_observer import ManagedPrestartObservation
    def observe(name,*,deadline):
        assert name=='managed-prestart' and time.monotonic()<deadline
        return ManagedPrestartObservation('fedora44-targeted-pair-v2',ContextBinding('d'*64,'e'*64))
    phase._dispatch=observe
    kind=FRAME_KIND_LITERAL
    if kind!='normal':
        response=phase._response
        def altered(record,request):
            value=json.loads(response(record,request))
            if kind=='extra':value['state']='COMPLETE'
            else:value['request_sha256']='0'*64
            return phase._json(value)+b'\\n'
        phase._response=altered
    raise SystemExit(phase._child_main(sys.argv[2:]))
phase._SCRIPT=str(pathlib.Path(__file__).resolve())
try:status=phase._parent('managed-prestart',time.monotonic())
except phase.PhaseError:
    sys.stderr.write('PHASE_REFUSED\\n');status=1
from qshd_selinux_process import _children
assert _children()==[]
try:os.waitpid(-1,os.WNOHANG)
except ChildProcessError:pass
else:raise AssertionError('owned child remains')
raise SystemExit(status)
""".replace('SOURCE_LITERAL', repr(str(SOURCE)))
        request, frame = self.frame()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            helper = root / 'owned-managed.py'
            environment = dict(os.environ, HOME=directory, XDG_CONFIG_HOME=directory,
                               XDG_CACHE_HOME=directory, TMPDIR=directory, HISTFILE='/dev/null',
                               PYTHONDONTWRITEBYTECODE='1')
            for kind in ('normal', 'extra', 'stale'):
                with self.subTest(kind=kind):
                    helper.write_text(program.replace('FRAME_KIND_LITERAL', repr(kind)))
                    result = subprocess.run([sys.executable, '-I', '-B', str(helper)], cwd=root,
                                            env=environment,
                                            capture_output=True, timeout=15)
                    self.assertEqual(result.returncode, 0 if kind == 'normal' else 1, result.stderr)
                    self.assertEqual(result.stdout, self.canonical(frame) if kind == 'normal' else b'')
                    self.assertEqual(result.stderr, b'' if kind == 'normal' else b'PHASE_REFUSED\n')

    def test_parent_keeps_original_owner_bounds_and_rejects_abnormal_custody(self):
        from qshd_selinux_process import _Outcome, _Streams
        request, frame = self.frame()
        raw = self.canonical(frame)
        normal = _Outcome(raw, b'', 0, None, True, natural=True, stdout_eof=True, stderr_eof=True)
        calls = []
        def run(argv, cwd, *, deadline):
            calls.append((argv, cwd, deadline))
            return _Streams(raw, b'')
        output = SimpleNamespace(buffer=io.BytesIO())
        with patch.object(self.phase, '_resources'), patch.object(self.phase.time, 'monotonic', return_value=101), \
             patch.object(self.phase, '_owner', return_value=SimpleNamespace(_last=normal, _run=run)), \
             patch.object(self.phase.sys, 'stdout', output):
            self.assertEqual(self.phase._parent('managed-prestart', 100), 0)
        self.assertEqual(calls, [(('/usr/bin/python3', '-I', '-B', self.phase._SCRIPT, self.phase._CHILD,
                                  request.decode(), '100', '530'), '/', 540)])
        self.assertEqual(output.buffer.getvalue(), raw)
        for change in ({'natural': False}, {'stdout_eof': False}, {'stderr_eof': False}, {'settled': False},
                       {'unreaped': (123,)}, {'group_term_attempts': 1}, {'adopted_term_attempts': 1},
                       {'kill_attempts': 1}, {'exit_code': 1}):
            with self.subTest(change=change):
                output = SimpleNamespace(buffer=io.BytesIO())
                owner = SimpleNamespace(_last=replace(normal, **change), _run=lambda *a, **k: _Streams(raw, b''))
                with patch.object(self.phase, '_resources'), patch.object(self.phase.time, 'monotonic', return_value=101), \
                     patch.object(self.phase, '_owner', return_value=owner), patch.object(self.phase.sys, 'stdout', output):
                    with self.assertRaises(self.phase.PhaseError): self.phase._parent('managed-prestart', 100)
                self.assertEqual(output.buffer.getvalue(), b'')
        output = SimpleNamespace(buffer=io.BytesIO())
        with patch.object(self.phase, '_resources'), patch.object(self.phase.time, 'monotonic', side_effect=[101, 101, 540]), \
             patch.object(self.phase, '_owner', return_value=SimpleNamespace(_last=normal, _run=run)), \
             patch.object(self.phase.sys, 'stdout', output):
            with self.assertRaises(self.phase.PhaseError): self.phase._parent('managed-prestart', 100)
        self.assertEqual(output.buffer.getvalue(), b'')


if __name__ == '__main__':
    unittest.main()
