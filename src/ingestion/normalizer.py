from datetime import datetime, timezone


def normalize_alert(alert: dict) -> dict:
    """Normalize an alert into the common SOC format."""

    normalized = alert.copy()

    normalized["alert_id"] = str(normalized["alert_id"]).strip()
    normalized["severity"] = normalized["severity"].upper()
    normalized["status"] = normalized["status"].upper()

    normalized["src_ip"] = str(normalized["src_ip"]).strip()
    normalized["username"] = str(normalized["username"]).strip()

    normalized["failed_attempts"] = int(normalized["failed_attempts"])
    normalized["successful_logins"] = int(
        normalized["successful_logins"]
    )

    timestamp = normalized["timestamp"]

    if timestamp.endswith("Z"):
        timestamp = timestamp[:-1] + "+00:00"

    parsed_timestamp = datetime.fromisoformat(timestamp)

    if parsed_timestamp.tzinfo is None:
        parsed_timestamp = parsed_timestamp.replace(
            tzinfo=timezone.utc
        )

    normalized["timestamp"] = parsed_timestamp.isoformat()

    return normalized