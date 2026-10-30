"""Execute generated wrappers with harmless synthetic source only."""
import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]

class EmbedTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('embed', ROOT/'packaging/selinux/embed_stop_guard.py')
        cls.m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.m)

    def test_exact_source_all_phases_and_failure_barrier(self):
        for phase in ('provider-pre', 'consumer-pre', 'provider-preun'):
            for code in (0, 7):
                source = f'import sys\nassert sys.argv[1:] == ["--phase", "{phase}", "--allow-unit-absent"]\nsys.exit({code})\n'.encode()
                wrapper = self.m.embed(source, phase, True)
                self.assertIn(source, wrapper)
                self.assertEqual(wrapper, self.m.embed(source, phase, True))
                with tempfile.TemporaryDirectory() as tmp:
                    result = subprocess.run(['/bin/sh'], input=wrapper+b'echo mutation > reached\n', cwd=tmp, capture_output=True)
                    self.assertEqual(result.returncode, code)
                    self.assertEqual((Path(tmp)/'reached').exists(), code == 0)

    def test_reject_untrusted_phase_and_unterminated_source(self):
        for source, phase in [(b'pass\n', '$(touch nope)'), (b'pass', 'consumer-pre')]:
            with self.assertRaises(ValueError): self.m.embed(source, phase)

    def test_exact_maintained_source_and_collision(self):
        source = (ROOT/'packaging/selinux/stop_guard.py').read_bytes()
        wrapper = self.m.embed(source, 'provider-pre')
        delimiter = self.m.delimiter(source).encode()
        extracted = wrapper.split(b"<<'"+delimiter+b"'\n", 1)[1].split(delimiter+b'\n', 1)[0]
        self.assertEqual(extracted, source)
        with self.assertRaises(ValueError):
            self.m.embed(b'pass\nCOLLISION\n', 'provider-pre', delimiter_override='COLLISION')

if __name__ == '__main__': unittest.main()
