"""Inventory checks use synthetic temporary files, never a fuzz runtime."""

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


CHECKER = Path(__file__).with_name("check_corpus.py")


class CorpusInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="qsh-corpus-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.corpus = self.root / "corpus"
        self.corpus.mkdir()
        self.manifest = self.root / "manifest.json"
        self.document = {
            "maximum_seed_files": 2,
            "maximum_total_bytes": 3,
            "files": [],
        }
        for name, data in [("empty", b""), ("sample", b"abc")]:
            (self.corpus / name).write_bytes(data)
            self.document["files"].append({
                "name": name,
                "bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            })
        # The manifest normally sits beside its seeds; it is not a seed.
        (self.corpus / "manifest.json").write_text("{}", encoding="utf-8")

    def run_check(self):
        self.manifest.write_text(json.dumps(self.document), encoding="utf-8")
        return subprocess.run(
            [sys.executable, str(CHECKER), str(self.manifest), str(self.corpus)],
            capture_output=True, text=True, timeout=5,
        )

    def assert_rejected(self, diagnostic):
        result = self.run_check()
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertIn(diagnostic, result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_valid_inventory_including_empty_file(self):
        result = self.run_check()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "Verified 2 corpus files\n")

    def test_same_size_content_change(self):
        (self.corpus / "sample").write_bytes(b"xyz")
        self.assert_rejected("SHA-256 mismatch")

    def test_size_change(self):
        (self.corpus / "sample").write_bytes(b"ab")
        self.assert_rejected("size mismatch")

    def test_missing_file(self):
        (self.corpus / "sample").unlink()
        self.assert_rejected("file inventory mismatch")

    def test_unlisted_file(self):
        (self.corpus / "extra").write_bytes(b"")
        self.assert_rejected("file inventory mismatch")

    def test_duplicate_entry(self):
        self.document["files"][1] = self.document["files"][0]
        self.assert_rejected("duplicate seed name")

    def test_file_count_budget(self):
        self.document["maximum_seed_files"] = 1
        self.assert_rejected("file count exceeds")

    def test_byte_budget(self):
        self.document["maximum_total_bytes"] = 2
        self.assert_rejected("total bytes exceed")

    def test_non_file_entry(self):
        (self.corpus / "sample").unlink()
        (self.corpus / "sample").mkdir()
        self.assert_rejected("not a regular file")

    def test_symlink_entry(self):
        (self.corpus / "sample").unlink()
        outside = self.root / "outside"
        outside.write_bytes(b"abc")
        (self.corpus / "sample").symlink_to(outside)
        self.assert_rejected("not a regular file")

    def test_invalid_manifest_fields(self):
        for field, value in [
            ("maximum_total_bytes", -1),
            ("maximum_seed_files", True),
            ("files", None),
            ("files", [None]),
            ("files", [{"name": "sample", "bytes": -1, "sha256": "0" * 64}]),
            ("files", [{"name": "sample", "bytes": 3, "sha256": "invalid"}]),
        ]:
            with self.subTest(field=field):
                original = self.document[field]
                self.document[field] = value
                self.assert_rejected("invalid manifest")
                self.document[field] = original

    def test_unreadable_or_invalid_manifest_reports_error(self):
        for contents in [None, "{", "[]"]:
            with self.subTest(contents=contents):
                if contents is not None:
                    self.manifest.write_text(contents, encoding="utf-8")
                result = subprocess.run(
                    [sys.executable, str(CHECKER), str(self.manifest), str(self.corpus)],
                    capture_output=True, text=True, timeout=5,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Corpus check failed:", result.stderr)
                self.assertNotIn("Traceback", result.stderr)

    def test_missing_corpus_directory(self):
        self.corpus = self.root / "missing"
        self.assert_rejected("Corpus check failed:")

    def test_committed_corpus(self):
        corpus_root = CHECKER.parent.parent / "corpus"
        targets = sorted(path for path in corpus_root.iterdir() if path.is_dir())
        self.assertEqual(len(targets), 6)
        for target in targets:
            with self.subTest(target=target.name):
                result = subprocess.run(
                    [sys.executable, str(CHECKER), str(target / "manifest.json"),
                     str(target)],
                    capture_output=True, text=True, timeout=5,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("Verified ", result.stdout)

    def test_names_are_single_path_components(self):
        for name in ["../sample", "/sample", "", ".", "..", "dir/sample", "dir\\sample"]:
            with self.subTest(name=name):
                self.document["files"][1]["name"] = name
                self.assert_rejected("invalid seed name")


if __name__ == "__main__":
    unittest.main()
