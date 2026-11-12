import tempfile
import unittest
from pathlib import Path

from src.cases.case_store import CaseStore


class TestCaseStore(unittest.TestCase):

    def test_update_preserves_existing_case_fields(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "test_cases.db"
            store = CaseStore(str(db_path))

            case = {
                "case_id": "CASE-001",
                "alert_id": "ALERT-001",
                "status": "OPEN",
                "severity": "HIGH",
                "priority": "P1",
                "risk_level": "CRITICAL",
                "risk_score": 100,
                "investigation": {
                    "summary": "Brute force investigation"
                },
                "evidence": [],
                "notes": [],
            }

            store.create(case)

            updated = store.update(
                "CASE-001",
                {
                    "status": "IN_PROGRESS",
                    "assigned_analyst": "james",
                },
            )

            self.assertEqual(
                updated["case_id"],
                "CASE-001",
            )

            self.assertEqual(
                updated["alert_id"],
                "ALERT-001",
            )

            self.assertEqual(
                updated["status"],
                "IN_PROGRESS",
            )

            self.assertEqual(
                updated["assigned_analyst"],
                "james",
            )

            self.assertEqual(
                updated["risk_score"],
                100,
            )

            self.assertEqual(
                updated["investigation"]["summary"],
                "Brute force investigation",
            )

            persisted = store.get("CASE-001")

            self.assertEqual(
                persisted["case_id"],
                "CASE-001",
            )

            self.assertEqual(
                persisted["status"],
                "IN_PROGRESS",
            )

            self.assertEqual(
                persisted["assigned_analyst"],
                "james",
            )


if __name__ == "__main__":
    unittest.main()