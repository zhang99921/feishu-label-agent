"""Local strategy tests. This is NOT a Feishu API or production-system test.

Assumptions: one writer process, durable and immediately visible record writes,
and no direct inventory edits outside that writer. Live validation is required.
"""
from __future__ import annotations

import copy
import hashlib
import json
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path


class Conflict(Exception):
    pass


class InjectedCrash(Exception):
    pass


class FakeRemote:
    """Retained dictionaries emulate storage across writer restart, not disk durability."""

    def __init__(self):
        self.cargo = {"TEST-BOX": {"state": "NEW", "location": None,
                                  "version": 0, "last_operation": None}}
        self.locations = {"TEST-A": True, "TEST-B": True, "DISABLED": False}
        self.operations = {}
        self.logs = {}
        self.fail_at = None

    def checkpoint(self, name):
        if self.fail_at == name:
            self.fail_at = None
            raise InjectedCrash(name)


class SingleWriter:
    """A strategy fixture with global serialization and a write-ahead operation record.

    It cannot coordinate multiple writer processes. Its assumptions must not be
    silently substituted for remote database guarantees.
    """

    def __init__(self, remote):
        self.remote = remote
        self.lock = threading.Lock()

    @staticmethod
    def digest(payload):
        data = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(data.encode()).hexdigest()

    def submit(self, key, payload, *, authorized=True):
        if not authorized:
            raise PermissionError("not authorized")
        with self.lock:
            fingerprint = self.digest(payload)
            previous = self.remote.operations.get(key)
            if previous:
                if previous["fingerprint"] != fingerprint:
                    raise Conflict("idempotency key reused with another payload")
                if previous["phase"] == "DONE":
                    return copy.deepcopy(previous["result"])
                self._recover_one(key)
                return copy.deepcopy(self.remote.operations[key]["result"])
            # Finish all unresolved work BEFORE accepting another business operation.
            for pending_key in list(self.remote.operations):
                if self.remote.operations[pending_key]["phase"] != "DONE":
                    self._recover_one(pending_key)
            cargo_id = payload["cargo"]
            current = self.remote.cargo.get(cargo_id)
            if current is None:
                raise Conflict("unknown cargo")
            if current["version"] != payload["expected_version"]:
                raise Conflict("stale version")
            if payload["action"] in ("IN", "REENTER"):
                required_state = "NEW" if payload["action"] == "IN" else "OUT"
                if current["state"] != required_state:
                    raise Conflict("explicit reentry required or invalid inbound state")
                if not self.remote.locations.get(payload["location"], False):
                    raise Conflict("location unavailable")
                target = dict(state="IN", location=payload["location"])
            elif payload["action"] == "OUT":
                if current["state"] != "IN":
                    raise Conflict("already outside")
                target = dict(state="OUT", location=None)
            elif payload["action"] == "MOVE":
                if current["state"] != "IN":
                    raise Conflict("outside cargo cannot move")
                if not self.remote.locations.get(payload["location"], False):
                    raise Conflict("location unavailable")
                if current["location"] == payload["location"]:
                    raise Conflict("same location")
                target = dict(state="IN", location=payload["location"])
            else:
                raise Conflict("unknown operation")
            before = copy.deepcopy(current)
            after = dict(target, version=current["version"] + 1, last_operation=key)
            self.remote.operations[key] = dict(
                fingerprint=fingerprint, cargo=cargo_id, before=before, after=after,
                phase="PREPARED", result=None)
            self.remote.checkpoint("after_prepare")
            self._recover_one(key)
            self.remote.checkpoint("response_lost")
            return copy.deepcopy(self.remote.operations[key]["result"])

    def _recover_one(self, key):
        operation = self.remote.operations[key]
        if operation["phase"] == "DONE":
            return
        current = self.remote.cargo[operation["cargo"]]
        if current == operation["before"]:
            self.remote.cargo[operation["cargo"]] = copy.deepcopy(operation["after"])
        elif current != operation["after"]:
            # Do not overwrite unrecognized/manual/concurrent changes.
            raise Conflict("recovery requires reconciliation")
        self.remote.checkpoint("after_cargo")
        # Dictionary key uniqueness is a fixture assumption, NOT a Feishu guarantee.
        self.remote.logs.setdefault(key, dict(cargo=operation["cargo"],
                                             before=operation["before"],
                                             after=operation["after"]))
        self.remote.checkpoint("after_log")
        operation["result"] = dict(ok=True, operation=key,
                                   version=operation["after"]["version"])
        operation["phase"] = "DONE"


def inbound(version=0, cargo="TEST-BOX", location="TEST-A"):
    return dict(action="IN", cargo=cargo, location=location, expected_version=version)


class ReliabilityTests(unittest.TestCase):
    def setUp(self):
        self.store = FakeRemote()
        self.writer = SingleWriter(self.store)

    def test_in_move_out_history(self):
        self.writer.submit("in", inbound())
        self.writer.submit("move", dict(action="MOVE", cargo="TEST-BOX",
                                       location="TEST-B", expected_version=1))
        self.writer.submit("out", dict(action="OUT", cargo="TEST-BOX", expected_version=2))
        self.assertEqual(self.store.cargo["TEST-BOX"]["state"], "OUT")
        self.assertIsNone(self.store.cargo["TEST-BOX"]["location"])
        self.assertEqual(len(self.store.logs), 3)

    def test_duplicate_concurrent_requests_replay_one_result(self):
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _: self.writer.submit("same", inbound()), range(24)))
        self.assertTrue(all(result == results[0] for result in results))
        self.assertEqual(len(self.store.logs), 1)
        self.assertEqual(self.store.cargo["TEST-BOX"]["version"], 1)

    def test_different_keys_with_same_stale_version_only_one_succeeds(self):
        def invoke(i):
            try:
                return self.writer.submit(str(i), inbound())["ok"]
            except Conflict:
                return False
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(invoke, range(24)))
        self.assertEqual(sum(results), 1)
        self.assertEqual(len(self.store.logs), 1)

    def test_key_payload_mismatch_rejected(self):
        self.writer.submit("same", inbound())
        with self.assertRaises(Conflict):
            self.writer.submit("same", inbound(location="TEST-B"))

    def test_completed_request_still_checks_permissions(self):
        self.writer.submit("same", inbound())
        with self.assertRaises(PermissionError):
            self.writer.submit("same", inbound(), authorized=False)

    def test_lost_response_replays_without_second_change(self):
        self.store.fail_at = "response_lost"
        with self.assertRaises(InjectedCrash):
            self.writer.submit("same", inbound())
        result = self.writer.submit("same", inbound())
        self.assertTrue(result["ok"])
        self.assertEqual(self.store.cargo["TEST-BOX"]["version"], 1)
        self.assertEqual(len(self.store.logs), 1)

    def test_restart_recovers_each_partial_write_boundary(self):
        for boundary in ["after_prepare", "after_cargo", "after_log"]:
            with self.subTest(boundary=boundary):
                store = FakeRemote()
                writer = SingleWriter(store)
                store.fail_at = boundary
                with self.assertRaises(InjectedCrash):
                    writer.submit("operation", inbound())
                restarted = SingleWriter(store)
                result = restarted.submit("operation", inbound())
                self.assertTrue(result["ok"])
                self.assertEqual(store.cargo["TEST-BOX"]["version"], 1)
                self.assertEqual(len(store.logs), 1)

    def test_unknown_and_disabled_targets_do_not_change_state(self):
        for payload in [inbound(cargo="UNKNOWN"), inbound(location="DISABLED"),
                        inbound(location="UNKNOWN")]:
            with self.subTest(payload=payload):
                before = copy.deepcopy(self.store.cargo)
                with self.assertRaises(Conflict):
                    self.writer.submit(str(payload), payload)
                self.assertEqual(before, self.store.cargo)
                self.assertFalse(self.store.logs)

    def test_late_old_outbound_cannot_remove_new_stay(self):
        self.writer.submit("in1", inbound())
        old = dict(action="OUT", cargo="TEST-BOX", expected_version=1)
        self.writer.submit("out1", old)
        reentry = inbound(version=2, location="TEST-B")
        reentry["action"] = "REENTER"
        self.writer.submit("in2", reentry)
        with self.assertRaises(Conflict):
            self.writer.submit("late-different-key", old)
        self.writer.submit("out1", old)  # Replay original success, no new mutation.
        self.assertEqual(self.store.cargo["TEST-BOX"]["location"], "TEST-B")
        self.assertEqual(self.store.cargo["TEST-BOX"]["version"], 3)

    def test_outside_cargo_cannot_move(self):
        with self.assertRaises(Conflict):
            self.writer.submit("move", dict(action="MOVE", cargo="TEST-BOX",
                                            location="TEST-B", expected_version=0))

    def test_outbound_requires_explicit_reentry(self):
        self.writer.submit("in", inbound())
        self.writer.submit("out", dict(action="OUT", cargo="TEST-BOX", expected_version=1))
        with self.assertRaises(Conflict):
            self.writer.submit("implicit", inbound(version=2))
        reentry = inbound(version=2)
        reentry["action"] = "REENTER"
        self.writer.submit("explicit", reentry)
        self.assertEqual(self.store.cargo["TEST-BOX"]["state"], "IN")
        self.assertEqual(len(self.store.logs), 3)

    def test_reentry_cannot_replace_first_entry(self):
        payload = inbound()
        payload["action"] = "REENTER"
        with self.assertRaises(Conflict):
            self.writer.submit("wrong", payload)
        self.assertEqual(self.store.cargo["TEST-BOX"]["state"], "NEW")

    def test_second_outbound_with_new_key_is_rejected(self):
        self.writer.submit("in", inbound())
        self.writer.submit("out", dict(action="OUT", cargo="TEST-BOX", expected_version=1))
        with self.assertRaises(Conflict):
            self.writer.submit("out-again", dict(action="OUT", cargo="TEST-BOX", expected_version=2))
        self.assertEqual(len(self.store.logs), 2)

    def test_same_location_move_is_rejected(self):
        self.writer.submit("in", inbound())
        with self.assertRaises(Conflict):
            self.writer.submit("same-location", dict(action="MOVE", cargo="TEST-BOX",
                                                    location="TEST-A", expected_version=1))
        self.assertEqual(len(self.store.logs), 1)

    def test_unresolved_operation_recovers_before_new_operation(self):
        self.store.fail_at = "after_cargo"
        with self.assertRaises(InjectedCrash):
            self.writer.submit("in", inbound())
        self.writer = SingleWriter(self.store)
        self.writer.submit("out", dict(action="OUT", cargo="TEST-BOX", expected_version=1))
        self.assertEqual(len(self.store.logs), 2)
        self.assertTrue(all(op["phase"] == "DONE" for op in self.store.operations.values()))

    def test_external_edit_blocks_recovery_instead_of_overwriting(self):
        self.store.fail_at = "after_cargo"
        with self.assertRaises(InjectedCrash):
            self.writer.submit("in", inbound())
        self.store.cargo["TEST-BOX"]["location"] = "MANUAL-EDIT"
        with self.assertRaises(Conflict):
            SingleWriter(self.store).submit("in", inbound())
        self.assertEqual(self.store.cargo["TEST-BOX"]["location"], "MANUAL-EDIT")

    def test_negative_control_uncoordinated_writers_lose_an_update(self):
        barrier = threading.Barrier(2)
        shared = {"version": 0}
        accepted = []
        def unsafe_writer():
            version = shared["version"]
            barrier.wait()
            shared["version"] = version + 1
            accepted.append(True)
        with ThreadPoolExecutor(max_workers=2) as executor:
            list(executor.map(lambda _: unsafe_writer(), range(2)))
        self.assertEqual(len(accepted), 2)
        self.assertEqual(shared["version"], 1)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(ReliabilityTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = dict(
        mode="LOCAL_FAULT_INJECTION_ONLY", tests=result.testsRun,
        failures=len(result.failures), errors=len(result.errors),
        feishu_http_tested=False, feishu_records_modified=0,
        live_status="See http_results.local.json; this fixture does not call the remote API",
        assumptions=["single writer process", "writes durable and immediately visible",
                     "no out-of-band edits", "fake dictionary uniqueness is not an API guarantee"],
        live_checks_pending=["app table permissions", "typed field writes", "read-after-write visibility",
                             "remote duplicate creation", "concurrent stale updates", "ambiguous HTTP timeouts",
                             "restart recovery on real records", "rate-limit recovery"])
    Path(__file__).with_name("local_results.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    raise SystemExit(not result.wasSuccessful())
