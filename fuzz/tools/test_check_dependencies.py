import copy
import unittest
from unittest.mock import patch
from pathlib import Path
import tempfile

import check_dependencies as checker


def graph(packages):
    return {"packages": packages, "resolve": {"nodes": [
        {"id": p["id"], "features": p.get("features", [])} for p in packages
    ]}}


def package(name, version="1.0.0", source="registry+test", path="/repo"):
    return {"id": name + version + str(source), "name": name,
            "version": version, "source": source,
            "manifest_path": path + "/Cargo.toml"}


class DependencyTests(unittest.TestCase):
    def setUp(self):
        self.product = graph([package("vte", "0.15.0", None, "/repo/vendor/vte"),
                              package("shared")])
        self.fuzz = copy.deepcopy(self.product)

    def test_equal_graphs(self):
        self.assertEqual(checker.compare(self.product, self.fuzz), [])

    def test_same_version_wrong_source(self):
        self.fuzz["packages"][0]["source"] = "registry+test"
        self.assertTrue(checker.compare(self.product, self.fuzz))

    def test_same_version_wrong_local_path(self):
        self.fuzz["packages"][0]["manifest_path"] = "/other/vte/Cargo.toml"
        self.assertTrue(checker.compare(self.product, self.fuzz))

    def test_shared_version_drift(self):
        self.fuzz["packages"][1]["version"] = "2.0.0"
        self.assertTrue(checker.compare(self.product, self.fuzz))

    def test_intentional_fuzz_only_and_feature_differences(self):
        for name in ("libfuzzer-sys", "arbitrary", "jobserver"):
            self.fuzz["packages"].append(package(name))
        self.fuzz["packages"].append(package("qsh-channel-fuzz", source=None))
        self.fuzz["resolve"]["nodes"][1]["features"] = ["std"]
        self.assertEqual(checker.compare(self.product, self.fuzz), [])

    def test_unreviewed_fuzz_only_dependency(self):
        self.fuzz["packages"].append(package("unexpected"))
        self.assertTrue(checker.compare(self.product, self.fuzz))

    def test_product_only_dependency_or_version_is_allowed(self):
        self.product["packages"].extend([package("product-only"), package("shared", "2.0.0")])
        self.assertEqual(checker.compare(self.product, self.fuzz), [])


class LockedPreflightTests(unittest.TestCase):
    def test_metadata_is_locked_and_offline(self):
        with patch.object(checker.subprocess, "check_output", return_value=b'{}') as run:
            checker.metadata(Path("/repo"), "fuzz/Cargo.toml", True)
        self.assertEqual(run.call_args.args[0], [
            "cargo", "metadata", "--format-version", "1", "--locked",
            "--manifest-path", "/repo/fuzz/Cargo.toml", "--offline"])

    def test_hash_detects_either_lock_changing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "fuzz").mkdir()
            for lock in ("Cargo.lock", "fuzz/Cargo.lock"):
                (root / lock).write_text("original")
            original = checker.lock_hashes(root)
            for lock in original:
                (root / lock).write_text("changed")
                self.assertNotEqual(checker.lock_hashes(root), original)
                (root / lock).write_text("original")
