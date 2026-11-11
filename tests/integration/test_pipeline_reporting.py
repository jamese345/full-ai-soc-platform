import unittest
import json
import tempfile
from unittest.mock import patch

from src.pipeline import process_alerts


class TestPipelineReporting(unittest.TestCase):

    ALERT_FILE = "data/alerts/sample_alerts.json"

    @patch(
        "src.pipeline.AnomalyDetector.predict"
    )
    def test_pipeline_generates_reports(
        self,
        mock_predict,
    ):
        mock_predict.return_value = {
            "is_anomaly": False,
            "label": "NORMAL",
            "score": 0.05,
        }

        result = process_alerts(
            self.ALERT_FILE
        )

        self.assertIn(
            "reports",
            result,
        )

        self.assertEqual(
            len(result["reports"]),
            len(result["alerts"]),
        )

    @patch(
        "src.pipeline.AnomalyDetector.predict"
    )
    def test_each_alert_has_a_report(
        self,
        mock_predict,
    ):
        mock_predict.return_value = {
            "is_anomaly": False,
            "label": "NORMAL",
            "score": 0.05,
        }

        result = process_alerts(
            self.ALERT_FILE
        )

        for alert in result["alerts"]:
            alert_id = alert["alert_id"]

            self.assertIn(
                alert_id,
                result["reports"],
            )

            report = result["reports"][alert_id]

            self.assertEqual(
                report["report_type"],
                "SOC_CASE_REPORT",
            )

            self.assertEqual(
                report["case"]["alert_id"],
                alert_id,
            )

    @patch(
        "src.pipeline.AnomalyDetector.predict"
    )
    def test_report_contains_case_and_risk_data(
        self,
        mock_predict,
    ):
        mock_predict.return_value = {
            "is_anomaly": False,
            "label": "NORMAL",
            "score": 0.05,
        }

        result = process_alerts(
            self.ALERT_FILE
        )

        report = result["reports"]["SOC-0001"]

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

    @patch(
        "src.pipeline.AnomalyDetector.predict"
    )
    def test_report_matches_case(
        self,
        mock_predict,
    ):
        mock_predict.return_value = {
            "is_anomaly": False,
            "label": "NORMAL",
            "score": 0.05,
        }

        result = process_alerts(
            self.ALERT_FILE
        )

        for alert_id, case in result["cases"].items():
            report = result["reports"][alert_id]

            self.assertEqual(
                report["case"]["case_id"],
                case["case_id"],
            )

            self.assertEqual(
                report["case"]["status"],
                case["status"],
            )

            self.assertEqual(
                report["risk"]["risk_score"],
                case["risk_score"],
            )

    @patch(
        "src.pipeline.SOCReportGenerator"
    )
    @patch(
        "src.pipeline.AnomalyDetector.predict"
    )
    def test_pipeline_tracks_report_paths(
        self,
        mock_predict,
        mock_generator,
    ):
        mock_predict.return_value = {
            "is_anomaly": False,
            "label": "NORMAL",
            "score": 0.05,
        }

        mock_instance = (
            mock_generator.return_value
        )

        mock_instance.generate_and_save_report.side_effect = (
            lambda case: (
                case,
                f"reports/{case['case_id']}.json",
            )
        )

        result = process_alerts(
            self.ALERT_FILE
        )

        self.assertIn(
            "report_paths",
            result,
        )

        self.assertEqual(
            len(result["report_paths"]),
            len(result["alerts"]),
        )

    @patch(
        "src.pipeline.AnomalyDetector.predict"
    )
    def test_pipeline_saves_real_reports(
        self,
        mock_predict,
    ):
        mock_predict.return_value = {
            "is_anomaly": False,
            "label": "NORMAL",
            "score": 0.05,
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            with patch(
                "src.pipeline.SOCReportGenerator"
            ) as mock_generator:

                from src.reporting.report_generator import (
                    SOCReportGenerator,
                )

                real_generator = (
                    SOCReportGenerator(
                        reports_dir=temp_dir
                    )
                )

                mock_generator.return_value = (
                    real_generator
                )

                result = process_alerts(
                    self.ALERT_FILE
                )

                self.assertEqual(
                    len(result["report_paths"]),
                    len(result["alerts"]),
                )

                for path in result[
                    "report_paths"
                ].values():
                    with open(
                        path,
                        "r",
                        encoding="utf-8",
                    ) as file:
                        saved_report = json.load(
                            file
                        )

                    self.assertEqual(
                        saved_report[
                            "report_type"
                        ],
                        "SOC_CASE_REPORT",
                    )


if __name__ == "__main__":
    unittest.main()
