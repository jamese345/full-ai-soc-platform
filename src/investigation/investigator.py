ACTION_SUMMARIES = {
    "ESCALATE": "escalation",
    "INVESTIGATE": "investigation",
    "MONITOR": "monitoring",
    "CLOSE": "closure",
}


def build_investigation(
    alert: dict,
    detections: list[dict],
    anomaly: dict,
    risk: dict,
    iocs: dict,
    enriched_iocs: dict,
    mitre: list[dict],
) -> dict:
    """Build a structured SOC investigation from pipeline evidence."""

    evidence = []

    # ---------------------------------------------------------
    # Rule-based detection evidence
    # ---------------------------------------------------------
    for detection in detections:
        evidence.append({
            "type": "RULE_DETECTION",
            "name": detection["detection"],
            "severity": detection["severity"],
            "confidence": detection["confidence"],
            "details": detection["evidence"],
        })

    # ---------------------------------------------------------
    # Machine-learning anomaly evidence
    # ---------------------------------------------------------
    if anomaly["is_anomaly"]:
        evidence.append({
            "type": "ML_ANOMALY",
            "classification": anomaly["classification"],
            "score": anomaly["anomaly_score"],
        })

    # ---------------------------------------------------------
    # IP threat-intelligence evidence
    # ---------------------------------------------------------
    for ip in enriched_iocs.get("ips", []):
        evidence.append({
            "type": "IP_INTELLIGENCE",
            "indicator": ip["indicator"],
            "classification": ip["classification"],
            "reputation": ip["reputation"],
        })

    # ---------------------------------------------------------
    # Domain threat-intelligence evidence
    # ---------------------------------------------------------
    for domain in enriched_iocs.get("domains", []):
        evidence.append({
            "type": "DOMAIN_INTELLIGENCE",
            "indicator": domain["indicator"],
            "reputation": domain["reputation"],
        })

    # ---------------------------------------------------------
    # MITRE ATT&CK evidence
    # ---------------------------------------------------------
    for mapping in mitre:
        evidence.append({
            "type": "MITRE_ATTACK",
            "technique_id": mapping["technique_id"],
            "technique": mapping["name"],
            "tactics": mapping["tactics"],
        })

    # ---------------------------------------------------------
    # Investigation findings
    # ---------------------------------------------------------
    findings = []

    if detections:
        findings.append(
            f"{len(detections)} rule-based detection(s) "
            "identified suspicious activity."
        )

    if anomaly["is_anomaly"]:
        findings.append(
            "Machine-learning analysis identified anomalous behavior."
        )

    if mitre:
        technique_names = ", ".join(
            mapping["name"] for mapping in mitre
        )

        findings.append(
            "Activity maps to MITRE ATT&CK technique(s): "
            f"{technique_names}."
        )

    if iocs.get("ips"):
        findings.append(
            f"{len(iocs['ips'])} IP indicator(s) were extracted."
        )

    if iocs.get("domains"):
        findings.append(
            f"{len(iocs['domains'])} domain indicator(s) were extracted."
        )

    if iocs.get("urls"):
        findings.append(
            f"{len(iocs['urls'])} URL indicator(s) were extracted."
        )

    if iocs.get("hashes"):
        findings.append(
            f"{len(iocs['hashes'])} file hash indicator(s) were extracted."
        )

    # ---------------------------------------------------------
    # Natural-language action summary
    # ---------------------------------------------------------
    action_summary = ACTION_SUMMARIES.get(
        risk["recommended_action"],
        risk["recommended_action"].lower(),
    )

    # ---------------------------------------------------------
    # Final investigation object
    # ---------------------------------------------------------
    return {
        "alert_id": alert["alert_id"],
        "summary": (
            f"{risk['risk_level']} risk alert requiring "
            f"{action_summary}."
        ),
        "risk_level": risk["risk_level"],
        "priority": risk["priority"],
        "confidence": risk["confidence"],
        "findings": findings,
        "evidence": evidence,
        "recommended_action": risk["recommended_action"],
    }