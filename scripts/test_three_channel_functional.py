"""Deterministic controls; no qsh or daemon execution."""
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import sys
import time
from types import SimpleNamespace
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location("functional", Path(__file__).with_name("three_channel_functional.py"))
functional = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(functional)


def complete():
    summary = dict(held_bytes=0, released=True, final_state_marker=True,
                   bulk_exited=True, echo_exited=True, screen_exited=True,
                   bulk_bytes=4194304, echo_responses=32, blocked_sequence=1,
                   release_sequence=2, credit_recovered_sequence=3, raw_processed=4194304)
    record = dict(phase="complete", ok=True, error=None, driver_joined=True,
                  manager_joined=True, registered_cleanup_settled=True,
                  raw_bytes_retained=0, summary=summary)
    record.update(case="no-loss", relay_joined=True, relay=dict(error=None, receipt=dict(armed=True, server_after_arm=8, dropped=0, held=0, reordered=0, held_bytes=0, held_high_water=0, canceled_held=0)))
    return dict(exit_code=0, reason=None, cleanup_overrun=False, settled=True,
                output=json.dumps(record))


class FunctionalControls(unittest.TestCase):
    def test_complete_and_failed_receipts(self):
        good = complete()
        self.assertTrue(functional.validate(good)["ok"])
        for field, value in (("exit_code", 1), ("reason", "stop"),
                             ("cleanup_overrun", True), ("settled", False), ("output", "")):
            with self.subTest(field=field), self.assertRaises(ValueError):
                functional.validate(dict(good, **{field: value}))
        for mutation in (lambda r: r.update(ok=False),
                         lambda r: r.update(driver_joined=False),
                         lambda r: r["summary"].update(held_bytes=1),
                         lambda r: r["summary"].update(credit_recovered_sequence=2)):
            record = json.loads(good["output"])
            mutation(record)
            with self.assertRaises(ValueError):
                functional.validate(dict(good, output=json.dumps(record)))
        with self.assertRaises(ValueError):
            functional.validate(dict(good, output=good["output"] + "\n" + good["output"]))

    def test_late_provenance_failure_keeps_native_receipts(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "run"
            identity = dict(commit="fixture", tree="fixture", lock_sha256="fixture", script_sha256="fixture")
            # This controls late provenance, independently of live runner disk space.
            with mock.patch.object(functional, "source_identity", side_effect=[identity, ValueError("changed")]), \
                 mock.patch.object(functional, "sha", return_value="fixture"), \
                 mock.patch.object(functional, "subreaper"), \
                 mock.patch.object(functional, "children", return_value=[]), \
                 mock.patch.object(functional, "watch_resources"), \
                 mock.patch.object(functional, "resource_reason", return_value=None), \
                 mock.patch.object(functional.os, "statvfs", return_value=SimpleNamespace(f_bavail=16 * 1024**3, f_frsize=1)), \
                 mock.patch.object(functional, "run_owned", return_value=complete()):
                self.assertEqual(functional.execute(Path(sys.executable), root), 1)
            result = json.loads((root / "result.json").read_text())
            self.assertFalse(result["ok"])
            self.assertTrue(result["no_children"])
            self.assertIn("source verification failed after execution", result["stop_reasons"])
            self.assertTrue(result["record"]["driver_joined"])
            self.assertEqual((root / "output.log").read_text(), complete()["output"])

    def test_insufficient_reserve_refuses_before_state_or_native_execution(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "run"
            with mock.patch.object(functional, "source_identity", return_value={}), \
                 mock.patch.object(functional, "sha", return_value="fixture"), \
                 mock.patch.object(functional, "children", return_value=[]), \
                 mock.patch.object(functional.os, "statvfs", return_value=SimpleNamespace(f_bavail=0, f_frsize=1)) as space, \
                 mock.patch.object(functional, "create_state") as create, \
                 mock.patch.object(functional, "subreaper") as prepare, \
                 mock.patch.object(functional, "run_owned") as run:
                with self.assertRaisesRegex(ValueError, "^free reserve$"):
                    functional.execute(Path(sys.executable), root)
            space.assert_called_once_with(root.parent)
            create.assert_not_called()
            prepare.assert_not_called()
            run.assert_not_called()
            self.assertFalse(root.exists())

    def test_owned_python_child_capture_and_reaping(self):
        # Harmless ordinary Python children only; never qsh, SSH, a shell or PTY.
        self.assertEqual(functional.children(), [])
        functional.subreaper()
        for program, failed in (("print('owned-control')", False),
                                ("import os; os.write(1,b'x'*131072)", True)):
            result = functional.run_owned([sys.executable, "-I", "-B", "-c", program],
                                           {"PATH": "/usr/bin:/bin"}, time.monotonic() + 5,
                                           [], grace=1)
            self.assertTrue(result["settled"])
            self.assertFalse(result["cleanup_overrun"])
            self.assertEqual(functional.children(), [])
            self.assertLessEqual(len(result["output"]), functional.CAP)
            if failed:
                self.assertEqual(result["reason"], "output cap exceeded")
            else:
                self.assertIsNone(result["reason"])
                self.assertEqual(result["exit_code"], 0)
                self.assertIn("owned-control", result["output"])

    def test_fresh_state_and_private_modes(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "owned"
            functional.create_state(root)
            for directory in (root, *(root / n for n in ("home", "config", "cache", "tmp"))):
                functional.private_dir(directory)
            with self.assertRaises(FileExistsError):
                functional.create_state(root)
            bad = Path(temp) / "link"
            bad.symlink_to(Path(temp) / "absent")
            with self.assertRaises(FileExistsError):
                functional.create_state(bad)

    def test_resource_stop_is_sticky_and_thread_joins(self):
        with tempfile.TemporaryDirectory() as temp:
            old_cap = functional.EVIDENCE_CAP
            try:
                functional.EVIDENCE_CAP = -1
                request = []
                stop = threading.Event()
                worker = threading.Thread(target=functional.watch_resources, args=(Path(temp), request, stop))
                worker.start()
                worker.join(2)
                self.assertFalse(worker.is_alive())
                self.assertEqual(request, ["evidence cap"])
                stop.set()
                functional.watch_resources(Path(temp), request, stop)
                self.assertEqual(request, ["evidence cap"])
            finally:
                functional.EVIDENCE_CAP = old_cap




class RelayReceiptControls(unittest.TestCase):
    def test_fixed_fault_case_requires_actual_complete_relay_receipts(self):
        result = complete()
        record = json.loads(result['output'])
        record.update(case='loss-reorder', relay_joined=True,
                      relay=dict(error=None, receipt=dict(armed=True, server_after_arm=8,
                          dropped=1, held=1, reordered=1, held_bytes=0,
                          held_high_water=1234, canceled_held=0)))
        result['output'] = json.dumps(record)
        self.assertTrue(functional.validate(result, 'loss-reorder')['ok'])
        for mutation in (lambda r: r.update(case='no-loss'),
                         lambda r: r.update(relay=None),
                         lambda r: r['relay'].update(receipt=None),
                         lambda r: r['relay']['receipt'].update(dropped=True),
                         lambda r: r.update(relay_joined=False),
                         lambda r: r['relay'].update(error='send failure'),
                         lambda r: r['relay']['receipt'].update(armed=False),
                         lambda r: r['relay']['receipt'].update(dropped=0),
                         lambda r: r['relay']['receipt'].update(reordered=0),
                         lambda r: r['relay']['receipt'].update(held_bytes=1),
                         lambda r: r['relay']['receipt'].update(canceled_held=1)):
            changed = json.loads(result['output'])
            mutation(changed)
            with self.assertRaises(ValueError):
                functional.validate(dict(result, output=json.dumps(changed)), 'loss-reorder')
        with self.assertRaises(ValueError):
            functional.validate(result, 'no-loss')


if __name__ == "__main__":
    unittest.main()
