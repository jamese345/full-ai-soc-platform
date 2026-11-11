import tempfile
import unittest
from pathlib import Path

from src.cases.case_manager import CaseManager
from src.cases.case_store import CaseStore


class TestCaseManager(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()

        db_path = (
            Path(self.temp_dir.name)
            / "cases.db"
        )

        self.manager = CaseManager(
            CaseStore(str(db_path))
        )

        self.alert = {
            "alert_id": "SOC-0001",
            "severity": "HIGH",
        }

        self.investigation = {
            "summary": "Brute-force activity detected.",
            "findings": [
                "Multiple failed login attempts."
            ],
            "recommended_action": "ESCALATE",
        }

        self.risk = {
            "risk_level": "CRITICAL",
            "risk_score": 100,
            "priority": "P1",
            "action": "ESCALATE",
        }

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_create_case(self):
        case = self.manager.create_case(
            alert=self.alert,
            investigation=self.investigation,
            risk=self.risk,
        )

        self.assertEqual(
            case["case_id"],
            "CASE-SOC-0001",
        )

        self.assertEqual(
            case["alert_id"],
            "SOC-0001",
        )

        self.assertEqual(
            case["status"],
            "OPEN",
        )

        self.assertEqual(
            case["priority"],
            "P1",
        )

    def test_duplicate_case_returns_existing_case(self):
        first = self.manager.create_case(
            self.alert,
            self.investigation,
            self.risk,
        )

        second = self.manager.create_case(
            self.alert,
            self.investigation,
            self.risk,
        )

        self.assertEqual(
            first["case_id"],
            second["case_id"],
        )

        self.assertEqual(
            len(self.manager.list_cases()),
            1,
        )

    def test_get_case(self):
        created = self.manager.create_case(
            self.alert,
            self.investigation,
            self.risk,
        )

        case = self.manager.get_case(
            created["case_id"]
        )

        self.assertIsNotNone(case)

    def test_assign_case(self):
        case = self.manager.create_case(
            self.alert,
            self.investigation,
            self.risk,
        )

        updated = self.manager.assign_case(
            case["case_id"],
            "SOC Analyst",
        )

        self.assertEqual(
            updated["assigned_analyst"],
            "SOC Analyst",
        )

        self.assertEqual(
            updated["status"],
            "IN_PROGRESS",
        )

    def test_update_status(self):
        case = self.manager.create_case(
            self.alert,
            self.investigation,
            self.risk,
        )

        updated = self.manager.update_status(
            case["case_id"],
            "CONTAINED",
        )

        self.assertEqual(
            updated["status"],
            "CONTAINED",
        )

    def test_invalid_status_is_rejected(self):
        case = self.manager.create_case(
            self.alert,
            self.investigation,
            self.risk,
        )

        with self.assertRaises(ValueError):
            self.manager.update_status(
                case["case_id"],
                "INVALID",
            )

    def test_add_evidence(self):
        case = self.manager.create_case(
            self.alert,
            self.investigation,
            self.risk,
        )

        updated = self.manager.add_evidence(
            case["case_id"],
            {
                "type": "ip",
                "value": "192.168.1.50",
            },
        )

        self.assertEqual(
            len(updated["evidence"]),
            1,
        )

        self.assertEqual(
            updated["evidence"][0]["value"],
            "192.168.1.50",
        )

    def test_add_note(self):
        case = self.manager.create_case(
            self.alert,
            self.investigation,
            self.risk,
        )

        updated = self.manager.add_note(
            case["case_id"],
            "Reviewed brute-force evidence.",
        )

        self.assertEqual(
            len(updated["notes"]),
            1,
        )

        self.assertEqual(
            updated["notes"][0]["note"],
            "Reviewed brute-force evidence.",
        )

    def test_close_case(self):
        case = self.manager.create_case(
            self.alert,
            self.investigation,
            self.risk,
        )

        closed = self.manager.close_case(
            case["case_id"],
            "Confirmed brute-force activity and escalated.",
        )

        self.assertEqual(
            closed["status"],
            "CLOSED",
        )

        self.assertIn(
            "closed_at",
            closed,
        )

        self.assertEqual(
            closed["resolution"],
            "Confirmed brute-force activity and escalated.",
        )

    def test_empty_note_is_rejected(self):
        case = self.manager.create_case(
            self.alert,
            self.investigation,
            self.risk,
        )

        with self.assertRaises(ValueError):
            self.manager.add_note(
                case["case_id"],
                "",
            )

    def test_empty_resolution_is_rejected(self):
        case = self.manager.create_case(
            self.alert,
            self.investigation,
            self.risk,
        )

        with self.assertRaises(ValueError):
            self.manager.close_case(
                case["case_id"],
                "",
            )

    def test_missing_case_raises_error(self):
        with self.assertRaises(KeyError):
            self.manager.assign_case(
                "CASE-DOES-NOT-EXIST",
                "Analyst",
            )


if __name__ == "__main__":
    unittest.main()