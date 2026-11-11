def detect_brute_force(alert: dict) -> dict | None:
    """Detect potential brute-force authentication activity."""

    failed_attempts = alert["failed_attempts"]

    if failed_attempts >= 10:
        return {
            "rule_id": "DET-001",
            "rule_name": "Brute Force Detection",
            "alert_id": alert["alert_id"],
            "detection": "BRUTE_FORCE",
            "severity": "HIGH",
            "confidence": "HIGH",
            "evidence": {
                "failed_attempts": failed_attempts,
                "threshold": 10,
            },
            "recommended_action": "INVESTIGATE",
        }

    return None


def detect_suspicious_login(alert: dict) -> dict | None:
    """Detect failed attempts followed by a successful login."""

    failed_attempts = alert["failed_attempts"]
    successful_logins = alert["successful_logins"]

    if failed_attempts > 0 and successful_logins > 0:
        return {
            "rule_id": "DET-002",
            "rule_name": "Suspicious Login Detection",
            "alert_id": alert["alert_id"],
            "detection": "SUSPICIOUS_LOGIN",
            "severity": "HIGH",
            "confidence": "HIGH",
            "evidence": {
                "failed_attempts": failed_attempts,
                "successful_logins": successful_logins,
            },
            "recommended_action": "INVESTIGATE",
        }

    return None


def detect_suspicious_request(alert: dict) -> dict | None:
    """Detect explicitly flagged suspicious web requests."""

    if alert["event_type"] == "suspicious_request":
        return {
            "rule_id": "DET-003",
            "rule_name": "Suspicious Request Detection",
            "alert_id": alert["alert_id"],
            "detection": "SUSPICIOUS_REQUEST",
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "evidence": {
                "event_type": alert["event_type"],
            },
            "recommended_action": "INVESTIGATE",
        }

    return None