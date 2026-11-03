"""Offline fake-byte authority generation; no RPM or candidate execution."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/generate-selinux-consumer-authority.py'


def generator():
    assert SCRIPT.is_file(), 'offline authority generator missing'
    name = 'qsh_test_authority_generator'
    spec = importlib.util.spec_from_file_location(name, SCRIPT)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)+'\n').encode()


class GeneratorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.binary = self.root/'binary'
        self.binary.write_bytes(b'fake final non-executable binary\x00\xff')
        self.binary.chmod(0o600)
        self.pam = self.root/'pam'
        self.pam.write_bytes((ROOT/'packaging/pam.d/qshd.fedora-selinux').read_bytes())
        self.metadata = self.root/'metadata.json'
        self.document = {'schema': 1, 'package': {'name': 'qshd', 'epoch': 0, 'version': '0.5.0', 'release': '1', 'arch': 'x86_64'},
                         'files': [{'path': '/etc/pam.d/qshd', 'mode': 0o100644, 'owner': 'root', 'group': 'root', 'flags': 17},
                                   {'path': '/usr/bin/qshd', 'mode': 0o100755, 'owner': 'root', 'group': 'root', 'flags': 0}]}
        self.write_metadata()
        self.output = self.root/'output'

    def write_metadata(self):
        self.metadata.write_bytes(encoded(self.document))

    def run_generate(self, module=None, output=None):
        m = module or generator()
        return m.generate(self.binary, self.pam, self.metadata, output or self.output)

    def test_final_bytes_deterministic_authority_and_detached_receipt(self):
        m = generator()
        self.run_generate(m)
        self.assertEqual(sorted(p.name for p in self.output.iterdir()), ['consumer-rpm.json', 'generation-receipt.json'])
        manifest = (self.output/'consumer-rpm.json').read_bytes()
        doc = json.loads(manifest)
        self.assertEqual(manifest, encoded(doc))
        authority = m.ConsumerRpmAuthority(doc['schema'], m.RpmPackage(**doc['package']), tuple(m.RpmFileAuthority(**v) for v in doc['files']))
        self.assertEqual(authority.package.arch, 'x86_64')
        binary = next(v for v in doc['files'] if v['path']=='/usr/bin/qshd')
        self.assertEqual(binary['size'], len(self.binary.read_bytes()))
        self.assertEqual(binary['sha256'], hashlib.sha256(self.binary.read_bytes()).hexdigest())
        receipt = json.loads((self.output/'generation-receipt.json').read_bytes())
        self.assertEqual(receipt['manifest_sha256'], hashlib.sha256(manifest).hexdigest())
        self.assertEqual(receipt['build_metadata_sha256'], hashlib.sha256(encoded(self.document)).hexdigest())
        self.assertNotIn(str(self.root).encode(), manifest+(self.output/'generation-receipt.json').read_bytes())
        self.run_generate(m, self.root/'same')
        self.assertEqual(manifest, (self.root/'same/consumer-rpm.json').read_bytes())
        self.assertEqual((self.output/'generation-receipt.json').read_bytes(), (self.root/'same/generation-receipt.json').read_bytes())
        self.binary.write_bytes(b'post-transform different bytes')
        self.run_generate(m, self.root/'changed')
        self.assertNotEqual(manifest, (self.root/'changed/consumer-rpm.json').read_bytes())

    def test_arch_modes_and_normalized_metadata_ignore_umask(self):
        m = generator()
        self.document['package']['arch'] = 'aarch64'
        self.write_metadata()
        old = os.umask(0o777)
        try:
            self.run_generate(m)
        finally:
            os.umask(old)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        for name, mode in [('consumer-rpm.json', 0o644), ('generation-receipt.json', 0o600)]:
            self.assertEqual(stat.S_IMODE((self.output/name).stat().st_mode), mode)
        self.assertEqual(json.loads((self.output/'consumer-rpm.json').read_bytes())['package']['arch'], 'aarch64')

    def test_metadata_selected_predicates_and_strict_json(self):
        m = generator()
        changes = [('package', 'name', 'other'), ('package', 'arch', 'armv7'), ('package', 'epoch', True),
                   ('package', 'version', ''), ('file', 'mode', 0o100600), ('file', 'owner', 'builder'),
                   ('file', 'flags', 0), ('file', 'path', '/tmp/pam')]
        original = json.loads(encoded(self.document))
        for section, key, value in changes:
            self.document = json.loads(encoded(original))
            target = self.document['package'] if section=='package' else self.document['files'][0]
            target[key] = value
            self.write_metadata()
            with self.subTest(key=key, value=value), self.assertRaises(m.GenerationError):
                self.run_generate(m)
            self.assertFalse(self.output.exists())
        raw_cases = [b'{"schema":1,"schema":1}', b'{}', b'[]', b'{"schema":NaN}', b'\xff', b' '*16385]
        for raw in raw_cases:
            self.metadata.write_bytes(raw)
            with self.subTest(raw=raw[:20]), self.assertRaises(m.GenerationError):
                self.run_generate(m)
        self.document = original
        self.document['unknown'] = 1
        self.write_metadata()
        with self.assertRaises(m.GenerationError): self.run_generate(m)
        self.document = original.copy()
        self.document['files'] = list(reversed(original['files']))
        self.write_metadata()
        with self.assertRaises(m.GenerationError): self.run_generate(m)

    def test_noncanonical_pam_empty_and_bounded_sources(self):
        m = generator()
        for data in (b'legacy'*96+b'x', b'legacy'*107+b'xxxx', b'', b'x'*4097):
            self.pam.write_bytes(data)
            with self.subTest(length=len(data)), self.assertRaises(m.GenerationError): self.run_generate(m)
        self.pam.write_bytes((ROOT/'packaging/pam.d/qshd.fedora-selinux').read_bytes())
        self.binary.write_bytes(b'')
        with self.assertRaises(m.GenerationError): self.run_generate(m)
        self.binary.write_bytes(b'x'*9)
        with patch.object(m, 'MAX_BINARY', 8), self.assertRaises(m.GenerationError): self.run_generate(m)

    def test_links_special_files_and_ancestor_symlinks_refuse_without_blocking(self):
        m = generator()
        saved = self.binary.read_bytes()
        self.binary.unlink()
        self.binary.symlink_to(self.pam)
        with self.assertRaises(m.GenerationError): self.run_generate(m)
        self.binary.unlink()
        os.mkfifo(self.binary)
        with self.assertRaises(m.GenerationError): self.run_generate(m)
        self.binary.unlink()
        self.binary.write_bytes(saved)
        os.link(self.binary, self.root/'extra-link')
        with self.assertRaises(m.GenerationError): self.run_generate(m)
        (self.root/'extra-link').unlink()
        linked = self.root/'linked-dir'
        linked.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(m.GenerationError): m.generate(linked/'binary', self.pam, self.metadata, self.output)
        self.assertFalse(self.output.exists())

    def test_preexisting_output_and_input_alias_are_never_overwritten(self):
        m = generator()
        self.output.mkdir()
        marker = self.output/'foreign'
        marker.write_bytes(b'preserve')
        with self.assertRaises(m.GenerationError): self.run_generate(m)
        self.assertEqual(marker.read_bytes(), b'preserve')
        marker.unlink(); self.output.rmdir()
        self.output.symlink_to(self.root/'missing')
        with self.assertRaises(m.GenerationError): self.run_generate(m)
        self.assertTrue(self.output.is_symlink())
        with self.assertRaises(m.GenerationError): m.generate(self.binary, self.binary, self.metadata, self.root/'alias-output')

    def test_inplace_and_replacement_drift_refuse_before_publish(self):
        m = generator()
        for replacement in (False, True):
            with self.subTest(replacement=replacement):
                original = m._write
                changed = False
                def drift(*args, **kwargs):
                    nonlocal changed
                    result = original(*args, **kwargs)
                    if not changed:
                        changed = True
                        if replacement:
                            new = self.root/'replacement'; new.write_bytes(b'changed'); os.replace(new, self.binary)
                        else: self.binary.write_bytes(b'changed in place')
                    return result
                with patch.object(m, '_write', side_effect=drift), self.assertRaises(m.GenerationError): self.run_generate(m)
                self.assertFalse(self.output.exists())
                self.assertFalse(list(self.root.glob('.consumer-authority-*')))

    def test_parent_route_replacement_is_detected(self):
        m = generator()
        source = self.root/'source'; source.mkdir(); binary = source/'binary'; binary.write_bytes(b'fake')
        original = m._write
        moved = self.root/'moved'
        def drift(*args, **kwargs):
            result = original(*args, **kwargs)
            if source.exists(): source.rename(moved); source.mkdir()
            return result
        with patch.object(m, '_write', side_effect=drift), self.assertRaises(m.GenerationError):
            m.generate(binary, self.pam, self.metadata, self.output)
        self.assertFalse(self.output.exists())

    def test_prepublication_write_and_sync_failures_clean_only_owned_stage(self):
        m = generator()
        for name in ('_write', '_sync'):
            with self.subTest(name=name), patch.object(m, name, side_effect=OSError('private sensitive input')), self.assertRaises(m.GenerationError) as error:
                self.run_generate(m)
            self.assertNotIn('private', str(error.exception))
            self.assertFalse(self.output.exists())
            self.assertFalse(list(self.root.glob('.consumer-authority-*')))

    def test_after_rename_sync_failure_is_uncertain_and_preserves_output(self):
        m = generator()
        sync = m._sync
        def fail_after(fd):
            if self.output.exists(): raise OSError('ack lost')
            return sync(fd)
        with patch.object(m, '_sync', side_effect=fail_after), self.assertRaises(m.PublicationUncertain): self.run_generate(m)
        self.assertEqual(sorted(p.name for p in self.output.iterdir()), ['consumer-rpm.json', 'generation-receipt.json'])

    def test_rename_failure_preserves_uncertain_stage_and_foreign_paths(self):
        m = generator()
        with patch.object(m.os, 'rename', side_effect=OSError('rename')), self.assertRaises(m.PublicationUncertain): self.run_generate(m)
        self.assertFalse(self.output.exists())
        stages = list(self.root.glob('.consumer-authority-*'))
        self.assertEqual(len(stages), 1)
        self.assertEqual(len(list(stages[0].iterdir())), 2)

    def test_file_descriptors_close_on_success_and_failures(self):
        m = generator()
        if not Path('/proc/self/fd').is_dir(): self.skipTest('requires Linux FD inventory')
        before = set(os.listdir('/proc/self/fd'))
        self.run_generate(m)
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)
        self.binary.write_bytes(b'')
        with self.assertRaises(m.GenerationError): self.run_generate(m, self.root/'bad')
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)

    def test_metadata_whitespace_normalizes_but_package_identity_changes_receipt(self):
        m = generator()
        self.run_generate(m)
        self.metadata.write_text(json.dumps(self.document, indent=3))
        self.run_generate(m, self.root/'whitespace')
        self.assertEqual((self.output/'generation-receipt.json').read_bytes(), (self.root/'whitespace/generation-receipt.json').read_bytes())
        self.document['package']['epoch'] = 1
        self.write_metadata()
        self.run_generate(m, self.root/'epoch')
        self.assertNotEqual((self.output/'consumer-rpm.json').read_bytes(), (self.root/'epoch/consumer-rpm.json').read_bytes())

    def test_all_inputs_are_rechecked_after_writes_including_same_size_change(self):
        m = generator()
        for path in (self.binary, self.pam, self.metadata):
            original_bytes = path.read_bytes()
            write = m._write
            changed = False
            def change(*args, **kwargs):
                nonlocal changed
                result = write(*args, **kwargs)
                if not changed:
                    changed = True
                    raw = path.read_bytes()
                    path.write_bytes(bytes([raw[0] ^ 1])+raw[1:])
                return result
            with self.subTest(path=path.name), patch.object(m, '_write', side_effect=change), self.assertRaises(m.GenerationError): self.run_generate(m)
            self.assertFalse(self.output.exists())
            path.write_bytes(original_bytes)

    def test_output_created_during_staging_is_preserved(self):
        m = generator()
        write = m._write
        def collide(*args, **kwargs):
            result = write(*args, **kwargs)
            self.output.mkdir(exist_ok=True)
            return result
        with patch.object(m, '_write', side_effect=collide), self.assertRaises(m.GenerationError): self.run_generate(m)
        self.assertTrue(self.output.is_dir())
        self.assertFalse(list(self.output.iterdir()))
        self.assertFalse(list(self.root.glob('.consumer-authority-*')))

    def test_cleanup_does_not_remove_unknown_stage_content(self):
        m = generator()
        write = m._write
        foreign = None
        def fail(*args, **kwargs):
            nonlocal foreign
            result = write(*args, **kwargs)
            stage = next(self.root.glob('.consumer-authority-*'))
            foreign = stage/'foreign'
            foreign.write_bytes(b'unknown')
            raise OSError('write failed later')
        with patch.object(m, '_write', side_effect=fail), self.assertRaises(m.GenerationError): self.run_generate(m)
        self.assertEqual(foreign.read_bytes(), b'unknown')
        self.assertFalse(self.output.exists())

    def test_acquired_source_and_stage_fds_close_after_fstat_or_open_faults(self):
        m = generator()
        if not Path('/proc/self/fd').is_dir(): self.skipTest('requires Linux FD inventory')
        before = set(os.listdir('/proc/self/fd'))
        fstat = m.os.fstat
        def fault(fd):
            value = fstat(fd)
            if stat.S_ISREG(value.st_mode): raise OSError('fstat')
            return value
        with patch.object(m.os, 'fstat', side_effect=fault), self.assertRaises(m.GenerationError): self.run_generate(m)
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)
        open_file = m.os.open
        def stage_fault(path, *args, **kwargs):
            if str(path).startswith('.consumer-authority-'): raise OSError('open stage')
            return open_file(path, *args, **kwargs)
        with patch.object(m.os, 'open', side_effect=stage_fault), self.assertRaises(m.GenerationError): self.run_generate(m)
        self.assertEqual(set(os.listdir('/proc/self/fd')), before)
        self.assertFalse(list(self.root.glob('.consumer-authority-*')))

    def test_binary_hashing_uses_bounded_chunks_and_final_metadata(self):
        m = generator()
        self.binary.write_bytes(b'x'*(m.CHUNK*2+3))
        read = m.os.read
        requested = []
        def record(fd, count):
            requested.append(count)
            return read(fd, count)
        with patch.object(m.os, 'read', side_effect=record): self.run_generate(m)
        self.assertLessEqual(max(requested), 65536)
        doc = json.loads((self.output/'consumer-rpm.json').read_bytes())
        self.assertEqual(doc['files'][1]['size'], m.CHUNK*2+3)
        self.assertEqual(doc['files'][1]['sha256'], hashlib.sha256(self.binary.read_bytes()).hexdigest())

    def test_generated_manifest_roundtrips_through_real_protected_reader(self):
        m = generator()
        import qshd_selinux_rpm_query as rpm
        self.run_generate(m)
        installed = self.root/'installed'
        parent = installed/'usr/share/qshd'
        parent.mkdir(parents=True)
        installed.chmod(0o755)
        for directory in installed.rglob('*'):
            if directory.is_dir(): directory.chmod(0o755)
        manifest = parent/'consumer-rpm.json'
        manifest.write_bytes((self.output/'consumer-rpm.json').read_bytes())
        manifest.chmod(0o644)
        expected = rpm.ConsumerRpmAuthority(1, rpm.RpmPackage(**self.document['package']), tuple(
            rpm.RpmFileAuthority(size=len(source.read_bytes()),
                                 sha256=hashlib.sha256(source.read_bytes()).hexdigest(), **record)
            for record, source in zip(self.document['files'], (self.pam, self.binary))))
        # Hard dependency on the accepted real reader: old baseline must fail,
        # never skip or replace its parser with generator-side JSON validation.
        reader = rpm.ConsumerAuthorityReader(_root=installed, _uid=os.geteuid(),
                                             _gid=os.getegid(), _clock=lambda: 100.0)
        with reader.inspection(deadline=200.0) as lease:
            observed = lease.capture()
            self.assertEqual(observed, expected)
            lease.recheck(observed)
        with self.assertRaises(rpm.RpmQueryError): lease.recheck(observed)


if __name__ == '__main__':
    unittest.main()
