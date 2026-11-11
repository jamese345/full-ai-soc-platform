from datetime import datetime, timezone

from src.cases.case_store import CaseStore


VALID_STATUSES = {
    "OPEN",
    "IN_PROGRESS",
    "CONTAINED",
    "RESOLVED",
    "CLOSED",
}


class CaseManager:
    """Manage the lifecycle of SOC investigation cases."""

    def __init__(self, store: CaseStore | None = None):
        self.store = store or CaseStore()

    @staticmethod
    def _timestamp() -> str:
        """Return a UTC ISO timestamp."""

        return datetime.now(
            timezone.utc
        ).isoformat()

    def _generate_case_id(
        self,
        alert_id: str,
    ) -> str:
        """Generate a deterministic case ID from an alert ID."""

        return f"CASE-{alert_id}"

    def create_case(
        self,
        alert: dict,
        investigation: dict,
        risk: dict,
        ai_investigation: dict | None = None,
    ) -> dict:
        """Create a SOC case from investigation results."""

        alert_id = alert["alert_id"]

        case_id = self._generate_case_id(
            alert_id
        )

        existing = self.store.get(case_id)

        if existing:
            return existing

        case = {
            "case_id": case_id,
            "alert_id": alert_id,
            "created_at": self._timestamp(),
            "updated_at": self._timestamp(),
            "status": "OPEN",
            "assigned_analyst": None,
            "severity": alert.get(
                "severity",
                "UNKNOWN",
            ),
            "priority": risk.get(
                "priority",
                "P4",
            ),
            "risk_level": risk.get(
                "risk_level",
                "UNKNOWN",
            ),
            "risk_score": risk.get(
                "risk_score",
                0,
            ),
            "action": risk.get(
                "action",
                "INVESTIGATE",
            ),
            "investigation": investigation,
            "ai_investigation": (
                ai_investigation
                if ai_investigation
                else None
            ),
            "evidence": [],
            "notes": [],
        }

        return self.store.create(case)

    def get_case(
        self,
        case_id: str,
    ) -> dict | None:
        """Retrieve a case."""

        return self.store.get(case_id)

    def list_cases(self) -> list[dict]:
        """Return all cases."""

        return self.store.list_cases()

    def assign_case(
        self,
        case_id: str,
        analyst: str,
    ) -> dict:
        """Assign a case to a SOC analyst."""

        if not analyst or not analyst.strip():
            raise ValueError(
                "Analyst name cannot be empty."
            )

        case = self.store.update(
            case_id,
            {
                "assigned_analyst": analyst.strip(),
                "status": "IN_PROGRESS",
                "updated_at": self._timestamp(),
            },
        )

        return case

    def update_status(
        self,
        case_id: str,
        status: str,
    ) -> dict:
        """Update the case lifecycle status."""

        normalized_status = status.upper().strip()

        if normalized_status not in VALID_STATUSES:
            raise ValueError(
                f"Invalid case status: {status}"
            )

        return self.store.update(
            case_id,
            {
                "status": normalized_status,
                "updated_at": self._timestamp(),
            },
        )

    def add_evidence(
        self,
        case_id: str,
        evidence: dict | str,
    ) -> dict:
        """Add evidence to a case."""

        case = self.store.get(case_id)

        if case is None:
            raise KeyError(
                f"Case not found: {case_id}"
            )

        updated_evidence = case["evidence"]
        updated_evidence.append(evidence)

        return self.store.update(
            case_id,
            {
                "evidence": updated_evidence,
                "updated_at": self._timestamp(),
            },
        )

    def add_note(
        self,
        case_id: str,
        note: str,
    ) -> dict:
        """Add an analyst note to a case."""

        if not note or not note.strip():
            raise ValueError(
                "Note cannot be empty."
            )

        case = self.store.get(case_id)

        if case is None:
            raise KeyError(
                f"Case not found: {case_id}"
            )

        notes = case["notes"]

        notes.append(
            {
                "timestamp": self._timestamp(),
                "note": note.strip(),
            }
        )

        return self.store.update(
            case_id,
            {
                "notes": notes,
                "updated_at": self._timestamp(),
            },
        )

    def close_case(
        self,
        case_id: str,
        resolution: str,
    ) -> dict:
        """Resolve and close a case."""

        if not resolution or not resolution.strip():
            raise ValueError(
                "Resolution cannot be empty."
            )

        return self.store.update(
            case_id,
            {
                "status": "CLOSED",
                "resolution": resolution.strip(),
                "closed_at": self._timestamp(),
                "updated_at": self._timestamp(),
            },
        )