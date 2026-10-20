import unittest
import tempfile
from pathlib import Path
from unittest.mock import patch

from administration import AuditedWorkflow
from quantity_rules import RuleError, correction, partial, stored_boxes, undo, whole_boxes
from workflow_store import Store, TestPrincipal, Workflow, writer_gate, _GATE_LOCAL


def before(quantity=10):
    return dict(state="在区", version=1, location=["A"], batch=["batch"], last_operation="first",
                remaining_boxes=quantity, quantity_unit="箱", quantity_verified=True)


class QuantityTests(unittest.TestCase):
    def test_partial_keeps_location_until_last_box(self):
        current = before()
        self.assertEqual(partial(current, 3)["remaining_boxes"], 7)
        self.assertEqual(partial(current, 3)["location"], ["A"])
        result = partial(current, 10)
        self.assertEqual((result["remaining_boxes"], result["state"], result["location"]), (0, "已出区", []))

    def test_invalid_amounts_rejected(self):
        for value in (0, -1, True, 1.5, "2", None, 11):
            with self.subTest(value=value), self.assertRaises(RuleError):
                partial(before(), value)

    def test_unit_or_verification_unknown_rejected(self):
        for change in ({"quantity_unit": "套"}, {"quantity_verified": False}, {"remaining_boxes": None}):
            with self.subTest(change=change), self.assertRaises(RuleError):
                partial(dict(before(), **change), 1)

    def test_correction_cannot_silently_outbound(self):
        with self.assertRaises(RuleError):
            correction(before(), 0, "count checked", True)
        self.assertEqual(correction(before(), 7, "count checked", True)["remaining_boxes"], 7)

    def test_missing_confirmation_or_reason_rejected(self):
        for reason, confirmed in [("", True), ("checked", False), ("checked", "true")]:
            with self.subTest(reason=reason, confirmed=confirmed), self.assertRaises(RuleError):
                correction(before(), 7, reason, confirmed)

    def test_later_change_prevents_simple_undo(self):
        first, second = before(), dict(before(), remaining_boxes=7, version=2, last_operation="second")
        self.assertEqual(undo(second, {"before": first, "after": second}, "checked", True), first)
        with self.assertRaises(RuleError):
            undo(dict(second, version=3), {"before": first, "after": second}, "checked", True)

    def test_stored_quantity_does_not_round(self):
        self.assertEqual(stored_boxes("3"), 3)
        self.assertIsNone(stored_boxes(None))
        for value in ("3.5", "NaN", "Infinity", "-1", True):
            with self.subTest(value=value), self.assertRaises(RuleError):
                stored_boxes(value)


class AuditGateTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = patch("workflow_store.ROOT", Path(temporary.name))
        root.start()
        self.addCleanup(root.stop)

    def test_nested_gate_retains_outer_ownership(self):
        with writer_gate():
            with writer_gate():
                self.assertTrue(_GATE_LOCAL.held)
            self.assertTrue(_GATE_LOCAL.held)
        self.assertFalse(_GATE_LOCAL.held)

    def test_flush_and_request_share_one_serialization_scope(self):
        seen = []
        class FixtureAudit:
            def flush(self):
                seen.append(("flush", _GATE_LOCAL.held))
        with patch.object(Workflow, "submit", side_effect=lambda *args: seen.append(("submit", _GATE_LOCAL.held))):
            AuditedWorkflow(None, audit=FixtureAudit()).submit("key", {}, TestPrincipal("a", "operator", "batch"))
        self.assertEqual(seen, [("flush", True), ("submit", True)])


if __name__ == "__main__":
    unittest.main()
