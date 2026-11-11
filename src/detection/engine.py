from src.detection.rules import (
    detect_brute_force,
    detect_suspicious_login,
    detect_suspicious_request,
)


DETECTION_RULES = [
    detect_brute_force,
    detect_suspicious_login,
    detect_suspicious_request,
]


def detect_alert(alert: dict) -> list[dict]:
    """Run all detection rules against one alert."""

    detections = []

    for rule in DETECTION_RULES:
        result = rule(alert)

        if result is not None:
            detections.append(result)

    return detections


def detect_alerts(alerts: list[dict]) -> dict[str, list[dict]]:
    """Run detection rules against all alerts."""

    results = {}

    for alert in alerts:
        results[alert["alert_id"]] = detect_alert(alert)

    return results