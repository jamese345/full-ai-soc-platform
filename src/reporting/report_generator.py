import json
from datetime import datetime, timezone
from pathlib import Path


class SOCReportGenerator:
    """Generate and persist structured SOC investigation reports."""

    def __init__(
        self,
        reports_dir: str = "reports",
    ):
        self.reports_dir = Path(
            reports_dir
        )

    @staticmethod
    def _timestamp() -> str:
        """Return a UTC ISO timestamp."""

        return datetime.now(
            timezone.utc
        ).isoformat()

    def generate_case_report(
        self,
        case: dict,
    ) -> dict:
        """
        Generate a structured report for a SOC case.
        """

        investigation = case.get(
            "investigation",
            {},
        )

        ai_investigation = case.get(
            "ai_investigation"
        )

        return {
            "report_type": "SOC_CASE_REPORT",
            "generated_at": self._timestamp(),

            "case": {
                "case_id": case.get(
                    "case_id"
                ),
                "alert_id": case.get(
                    "alert_id"
                ),
                "status": case.get(
                    "status"
                ),
                "assigned_analyst": case.get(
                    "assigned_analyst"
                ),
                "created_at": case.get(
                    "created_at"
                ),
                "updated_at": case.get(
                    "updated_at"
                ),
            },

            "risk": {
                "severity": case.get(
                    "severity"
                ),
                "risk_level": case.get(
                    "risk_level"
                ),
                "risk_score": case.get(
                    "risk_score"
                ),
                "priority": case.get(
                    "priority"
                ),
                "action": case.get(
                    "action"
                ),
            },

            "investigation": {
                "summary": investigation.get(
                    "summary"
                ),
                "findings": investigation.get(
                    "findings",
                    [],
                ),
                "recommended_action": investigation.get(
                    "recommended_action"
                ),
            },

            "ai_investigation": self._build_ai_section(
                ai_investigation
            ),

            "evidence": case.get(
                "evidence",
                [],
            ),

            "notes": case.get(
                "notes",
                [],
            ),

            "resolution": case.get(
                "resolution"
            ),
        }

    @staticmethod
    def _build_ai_section(
        ai_investigation: dict | None,
    ) -> dict:
        """Build a safe AI investigation section."""

        if not ai_investigation:
            return {
                "status": "NOT_RUN",
                "response": None,
                "model": None,
                "error": None,
            }

        return {
            "status": ai_investigation.get(
                "status"
            ),
            "response": ai_investigation.get(
                "response"
            ),
            "model": ai_investigation.get(
                "model"
            ),
            "error": ai_investigation.get(
                "error"
            ),
        }

    def save_report(
        self,
        report: dict,
    ) -> Path:
        """
        Save a SOC report as JSON.

        Returns:
            Path to the saved report.
        """

        case_id = report.get(
            "case",
            {},
        ).get(
            "case_id"
        )

        if not case_id:
            raise ValueError(
                "Report must contain a case ID."
            )

        self.reports_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        report_path = (
            self.reports_dir
            / f"{case_id}.json"
        )

        with report_path.open(
            "w",
            encoding="utf-8",
        ) as file:
            json.dump(
                report,
                file,
                indent=2,
                ensure_ascii=False,
            )

        return report_path

    def generate_and_save_report(
        self,
        case: dict,
    ) -> tuple[dict, Path]:
        """
        Generate a report and persist it as JSON.
        """

        report = self.generate_case_report(
            case
        )

        report_path = self.save_report(
            report
        )

        return report, report_path

    def generate_executive_summary(
        self,
        case: dict,
    ) -> str:
        """Generate a concise executive summary."""

        case_id = case.get(
            "case_id",
            "UNKNOWN",
        )

        severity = case.get(
            "severity",
            "UNKNOWN",
        )

        risk_level = case.get(
            "risk_level",
            "UNKNOWN",
        )

        priority = case.get(
            "priority",
            "UNKNOWN",
        )

        action = case.get(
            "action",
            "UNKNOWN",
        )

        status = case.get(
            "status",
            "UNKNOWN",
        )

        return (
            f"SOC case {case_id} is currently "
            f"{status}. The alert was classified as "
            f"{severity} severity with a {risk_level} "
            f"risk level and {priority} priority. "
            f"The recommended response is "
            f"{action}."
        )
