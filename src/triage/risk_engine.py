SEVERITY_SCORES = {
    "LOW": 10,
    "MEDIUM": 25,
    "HIGH": 40,
    "CRITICAL": 50,
}


def calculate_risk_score(
    alert: dict,
    detections: list[dict],
    anomaly: dict,
) -> int:
    score = SEVERITY_SCORES.get(
        alert["severity"],
        0,
    )

    reasons = []

    if alert["failed_attempts"] >= 10:
        score += 20
        reasons.append(
            f"High failed-login count: "
            f"{alert['failed_attempts']}"
        )

    if alert["successful_logins"] > 0 and alert["failed_attempts"] > 0:
        score += 20
        reasons.append(
            "Successful login occurred after failed attempts"
        )

    detection_names = {
        detection["detection"]
        for detection in detections
    }

    if "BRUTE_FORCE" in detection_names:
        score += 15
        reasons.append("Brute-force activity detected")

    if "SUSPICIOUS_LOGIN" in detection_names:
        score += 15
        reasons.append("Suspicious login pattern detected")

    if "SUSPICIOUS_REQUEST" in detection_names:
        score += 10
        reasons.append("Suspicious request pattern detected")

    if anomaly["is_anomaly"]:
        score += 20
        reasons.append("ML anomaly detected")

    return min(score, 100)


def classify_risk(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def assign_priority(risk_level: str) -> str:
    priorities = {
        "CRITICAL": "P1",
        "HIGH": "P2",
        "MEDIUM": "P3",
        "LOW": "P4",
    }

    return priorities[risk_level]


def determine_confidence(
    detections: list[dict],
    anomaly: dict,
) -> str:
    detection_count = len(detections)

    if detection_count >= 2 and anomaly["is_anomaly"]:
        return "VERY_HIGH"

    if detection_count >= 1 or anomaly["is_anomaly"]:
        return "HIGH"

    return "MEDIUM"


def recommend_action(
    risk_level: str,
) -> str:
    actions = {
        "CRITICAL": "ESCALATE",
        "HIGH": "INVESTIGATE",
        "MEDIUM": "MONITOR",
        "LOW": "CLOSE",
    }

    return actions[risk_level]


def assess_risk(
    alert: dict,
    detections: list[dict],
    anomaly: dict,
) -> dict:
    score = calculate_risk_score(
        alert,
        detections,
        anomaly,
    )

    risk_level = classify_risk(score)

    return {
        "alert_id": alert["alert_id"],
        "risk_score": score,
        "risk_level": risk_level,
        "priority": assign_priority(risk_level),
        "confidence": determine_confidence(
            detections,
            anomaly,
        ),
        "recommended_action": recommend_action(
            risk_level,
        ),
    }