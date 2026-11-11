import json
from pathlib import Path


REQUIRED_FIELDS = {
    "alert_id",
    "timestamp",
    "source",
    "event_type",
    "severity",
    "src_ip",
    "username",
    "hostname",
    "description",
    "failed_attempts",
    "successful_logins",
    "status",
}


def load_alerts(file_path: str) -> list[dict]:
    """Load security alerts from a JSON file."""

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Alert file not found: {file_path}")

    with path.open("r", encoding="utf-8") as file:
        alerts = json.load(file)

    if not isinstance(alerts, list):
        raise ValueError("Alert data must be a list.")

    return alerts


def validate_alert(alert: dict) -> bool:
    """Validate that an alert contains the required fields."""

    missing_fields = REQUIRED_FIELDS - alert.keys()

    if missing_fields:
        raise ValueError(
            f"Alert {alert.get('alert_id', 'UNKNOWN')} "
            f"is missing fields: {sorted(missing_fields)}"
        )

    return True


def validate_alerts(alerts: list[dict]) -> bool:
    """Validate all alerts in a collection."""

    for alert in alerts:
        validate_alert(alert)

    return True