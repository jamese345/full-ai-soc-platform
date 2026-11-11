import unittest
import json
import tempfile
from pathlib import Path

from src.reporting.report_generator import (
    SOCReportGenerator,
)


class TestSOCReportGenerator(unittest.TestCase):

    def setUp(self):
        self.generator = SOCReportGenerator()

        self.case = {
            "case_id": "CASE-SOC-0001",
            "alert_id": "SOC-0001",
            "status": "OPEN",
            "assigned_analyst": "SOC Analyst",
            "created_at": "2026-11-11T10:00:00+00:00",
            "updated_at": "2026-11-11T10:05:00+00:00",
            "severity": "HIGH",
            "risk_level": "CRITICAL",
            "risk_score": 100,
            "priority": "P1",
            "action": "ESCALATE",
            "investigation": {
                "summary": (
                    "Critical brute-force activity detected."
                ),
                "findings": [
                    "Multiple failed login attempts.",
                    "Anomalous authentication behavior.",
                ],
                "recommended_action": "ESCALATE",
            },
            "ai_investigation": {
                "status": "COMPLETED",
                "response": (
                    "Evidence supports further investigation."
                ),
                "model": "gpt-5-mini",
                "error": None,
            },
            "evidence": [
                {
                    "type": "ip",
                    "value": "192.168.1.50",
                }
            ],
            "notes": [
                {
                    "timestamp": (
                        "2026-11-11T10:10:00+00:00"
                    ),
                    "note": (
                        "Reviewed authentication evidence."
                    ),
                }
            ],
            "resolution": None,
        }

    def test_generate_case_report(self):
        report = self.generator.generate_case_report(
            self.case
        )

        self.assertEqual(
            report["report_type"],
            "SOC_CASE_REPORT",
        )

        self.assertIn(
            "generated_at",
            report,
        )

        self.assertIn(
            "case",
            report,
        )

        self.assertIn(
            "risk",
            report,
        )

        self.assertIn(
            "investigation",
            report,
        )

        self.assertIn(
            "ai_investigation",
            report,
        )

        self.assertIn(
            "evidence",
            report,
        )

        self.assertIn(
            "notes",
            report,
        )

    def test_case_information_is_preserved(self):
        report = self.generator.generate_case_report(
            self.case
        )

        self.assertEqual(
            report["case"]["case_id"],
            "CASE-SOC-0001",
        )

        self.assertEqual(
            report["case"]["alert_id"],
            "SOC-0001",
        )

        self.assertEqual(
            report["case"]["status"],
            "OPEN",
        )

    def test_risk_information_is_preserved(self):
        report = self.generator.generate_case_report(
            self.case
        )

        self.assertEqual(
            report["risk"]["risk_level"],
            "CRITICAL",
        )

        self.assertEqual(
            report["risk"]["risk_score"],
            100,
        )

        self.assertEqual(
            report["risk"]["priority"],
            "P1",
        )

        self.assertEqual(
            report["risk"]["action"],
            "ESCALATE",
        )

    def test_investigation_information_is_preserved(self):
        report = self.generator.generate_case_report(
            self.case
        )

        investigation = report["investigation"]

        self.assertEqual(
            investigation["summary"],
            (
                "Critical brute-force activity detected."
            ),
        )

        self.assertEqual(
            len(investigation["findings"]),
            2,
        )

        self.assertEqual(
            investigation["recommended_action"],
            "ESCALATE",
        )

    def test_ai_investigation_is_preserved(self):
        report = self.generator.generate_case_report(
            self.case
        )

        ai = report["ai_investigation"]

        self.assertEqual(
            ai["status"],
            "COMPLETED",
        )

        self.assertEqual(
            ai["model"],
            "gpt-5-mini",
        )

        self.assertIsNone(
            ai["error"]
        )

    def test_evidence_is_preserved(self):
        report = self.generator.generate_case_report(
            self.case
        )

        self.assertEqual(
            len(report["evidence"]),
            1,
        )

        self.assertEqual(
            report["evidence"][0]["value"],
            "192.168.1.50",
        )

    def test_notes_are_preserved(self):
        report = self.generator.generate_case_report(
            self.case
        )

        self.assertEqual(
            len(report["notes"]),
            1,
        )

        self.assertEqual(
            report["notes"][0]["note"],
            "Reviewed authentication evidence.",
        )

    def test_ai_section_when_ai_was_not_run(self):
        case = dict(self.case)

        case["ai_investigation"] = None

        report = self.generator.generate_case_report(
            case
        )

        ai = report["ai_investigation"]

        self.assertEqual(
            ai["status"],
            "NOT_RUN",
        )

        self.assertIsNone(
            ai["response"]
        )

        self.assertIsNone(
            ai["model"]
        )

    def test_ai_error_is_preserved_as_safe_category(self):
        case = dict(self.case)

        case["ai_investigation"] = {
            "status": "LLM_ERROR",
            "response": (
                "The AI investigation request failed."
            ),
            "model": "gpt-5-mini",
            "error": "API_QUOTA_OR_RATE_LIMIT",
        }

        report = self.generator.generate_case_report(
            case
        )

        ai = report["ai_investigation"]

        self.assertEqual(
            ai["status"],
            "LLM_ERROR",
        )

        self.assertEqual(
            ai["error"],
            "API_QUOTA_OR_RATE_LIMIT",
        )

        self.assertNotIn(
            "raw",
            ai,
        )

    def test_executive_summary(self):
        summary = (
            self.generator.generate_executive_summary(
                self.case
            )
        )

        self.assertIn(
            "CASE-SOC-0001",
            summary,
        )

        self.assertIn(
            "CRITICAL",
            summary,
        )

        self.assertIn(
            "P1",
            summary,
        )

        self.assertIn(
            "ESCALATE",
            summary,
        )

    def test_executive_summary_uses_current_status(self):
        case = dict(self.case)

        case["status"] = "CLOSED"
        case["action"] = "CLOSE"

        summary = (
            self.generator.generate_executive_summary(
                case
            )
        )

        self.assertIn(
            "CLOSED",
            summary,
        )

        self.assertIn(
            "CLOSE",
            summary,
        )

    def test_save_report_creates_json_file(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            generator = SOCReportGenerator(
                reports_dir=temp_dir
            )

            report = generator.generate_case_report(
                self.case
            )

            report_path = generator.save_report(
                report
            )

            self.assertTrue(
                report_path.exists()
            )

            self.assertEqual(
                report_path.name,
                "CASE-SOC-0001.json",
            )

    def test_saved_report_contains_valid_json(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            generator = SOCReportGenerator(
                reports_dir=temp_dir
            )

            report = generator.generate_case_report(
                self.case
            )

            report_path = generator.save_report(
                report
            )

            with report_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                saved_report = json.load(
                    file
                )

            self.assertEqual(
                saved_report["case"]["case_id"],
                "CASE-SOC-0001",
            )

            self.assertEqual(
                saved_report["risk"]["priority"],
                "P1",
            )

    def test_generate_and_save_report(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            generator = SOCReportGenerator(
                reports_dir=temp_dir
            )

            report, report_path = (
                generator.generate_and_save_report(
                    self.case
                )
            )

            self.assertEqual(
                report["report_type"],
                "SOC_CASE_REPORT",
            )

            self.assertTrue(
                report_path.exists()
            )

    def test_save_report_requires_case_id(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            generator = SOCReportGenerator(
                reports_dir=temp_dir
            )

            report = {
                "report_type": "SOC_CASE_REPORT"
            }

            with self.assertRaises(
                ValueError
            ):
                generator.save_report(
                    report
                )

    def test_save_report_creates_missing_directory(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            reports_dir = (
                Path(temp_dir)
                / "nested"
                / "reports"
            )

            generator = SOCReportGenerator(
                reports_dir=str(
                    reports_dir
                )
            )

            report = generator.generate_case_report(
                self.case
            )

            report_path = generator.save_report(
                report
            )

            self.assertTrue(
                report_path.exists()
            )


if __name__ == "__main__":
    unittest.main()