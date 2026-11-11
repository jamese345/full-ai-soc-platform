def extract_features(alert: dict) -> dict:
    """Extract ML features from a normalized SOC alert."""
    return {
        "failed_attempts": alert["failed_attempts"],
        "successful_logins": alert["successful_logins"],
        "login_frequency": alert.get("login_frequency", 1),
        "unique_source_ips": alert.get("unique_source_ips", 1),
        "login_hour": alert.get("login_hour", 12),
        "session_duration": alert.get("session_duration", 60),
        "request_count": alert.get("request_count", 10),
    }