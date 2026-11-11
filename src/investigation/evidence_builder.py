def build_investigation_query(
    alert: dict,
    detections: list[dict],
    anomaly: dict,
    risk: dict,
    iocs: dict,
    enriched_iocs: dict,
    mitre: list[dict],
) -> str:
    """Build a focused RAG query from SOC investigation evidence."""

    query_parts = []

    # Alert context
    query_parts.append(
        f"Investigate {alert['event_type']} activity "
        f"from source IP {alert['src_ip']}."
    )

    query_parts.append(
        f"Alert severity is {alert['severity']} "
        f"with risk level {risk['risk_level']} "
        f"and priority {risk['priority']}."
    )

    # Rule detections
    if detections:
        detection_names = [
            detection["detection"]
            for detection in detections
        ]

        query_parts.append(
            "Rule detections: "
            + ", ".join(detection_names)
            + "."
        )

    # ML anomaly
    if anomaly["is_anomaly"]:
        query_parts.append(
            "Machine-learning analysis identified "
            "anomalous behavior."
        )
    else:
        query_parts.append(
            "Machine-learning analysis classified "
            "the behavior as normal."
        )

    # IOC context
    if iocs.get("ips"):
        query_parts.append(
            "IP indicators: "
            + ", ".join(iocs["ips"])
            + "."
        )

    if iocs.get("domains"):
        query_parts.append(
            "Domain indicators: "
            + ", ".join(iocs["domains"])
            + "."
        )

    if iocs.get("urls"):
        query_parts.append(
            "URL indicators were extracted."
        )

    if iocs.get("hashes"):
        query_parts.append(
            "File hash indicators were extracted."
        )

    # Threat intelligence
    threat_context = []

    for ip in enriched_iocs.get("ips", []):
        threat_context.append(
            f"{ip['indicator']} "
            f"classification={ip['classification']} "
            f"reputation={ip['reputation']}"
        )

    for domain in enriched_iocs.get("domains", []):
        threat_context.append(
            f"{domain['indicator']} "
            f"reputation={domain['reputation']}"
        )

    if threat_context:
        query_parts.append(
            "Threat intelligence context: "
            + "; ".join(threat_context)
            + "."
        )

    # MITRE ATT&CK
    if mitre:
        mitre_context = []

        for mapping in mitre:
            mitre_context.append(
                f"{mapping['technique_id']} "
                f"{mapping['name']}"
            )

        query_parts.append(
            "MITRE ATT&CK mappings: "
            + ", ".join(mitre_context)
            + "."
        )

    # Investigation objective
    query_parts.append(
        "Determine what the observed behavior may indicate, "
        "which evidence supports the assessment, "
        "what additional evidence should be collected, "
        "and what investigation steps are appropriate."
    )

    return " ".join(query_parts)