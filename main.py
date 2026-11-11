from src.pipeline import process_alerts


ALERT_FILE = "data/alerts/sample_alerts.json"


def print_header():
    print("=" * 70)
    print("FULL AI SOC ANALYST PLATFORM")
    print("=" * 70)


def print_alert_summary(
    alert,
    detections,
    anomaly,
    risk,
    iocs,
    enriched_iocs,
    mitre,
    investigation,
):
    alert_id = alert["alert_id"]

    print(
        f"[{alert_id}] "
        f"{alert['severity']} - "
        f"{alert['event_type']}"
    )

    # ---------------------------------------------------------
    # Rule Detection
    # ---------------------------------------------------------

    alert_detections = detections[alert_id]

    if alert_detections:
        for detection in alert_detections:
            print(
                f"  Rule Detection: "
                f"{detection['detection']} "
                f"({detection['severity']})"
            )
    else:
        print("  Rule Detection: NONE")

    # ---------------------------------------------------------
    # ML Detection
    # ---------------------------------------------------------

    alert_anomaly = anomaly[alert_id]

    print(
        f"  ML Detection: "
        f"{alert_anomaly['classification']} "
        f"(score={alert_anomaly['anomaly_score']:.4f})"
    )

    # ---------------------------------------------------------
    # Risk
    # ---------------------------------------------------------

    alert_risk = risk[alert_id]

    print(
        f"  Risk: "
        f"{alert_risk['risk_level']} "
        f"(score={alert_risk['risk_score']})"
    )

    print(
        f"  Priority: "
        f"{alert_risk['priority']} | "
        f"Confidence: "
        f"{alert_risk['confidence']}"
    )

    print(
        f"  Action: "
        f"{alert_risk['recommended_action']}"
    )

    # ---------------------------------------------------------
    # IOC Extraction
    # ---------------------------------------------------------

    alert_iocs = iocs[alert_id]

    ioc_count = sum(
        len(values)
        for values in alert_iocs.values()
    )

    print(
        f"  IOC Count: {ioc_count}"
    )

    if alert_iocs["ips"]:
        print(
            f"  IPs: "
            f"{', '.join(alert_iocs['ips'])}"
        )

    if alert_iocs["domains"]:
        print(
            f"  Domains: "
            f"{', '.join(alert_iocs['domains'])}"
        )

    if alert_iocs["urls"]:
        print(
            f"  URLs: "
            f"{', '.join(alert_iocs['urls'])}"
        )

    if alert_iocs["hashes"]:
        print(
            f"  Hashes: "
            f"{', '.join(alert_iocs['hashes'])}"
        )

    # ---------------------------------------------------------
    # Threat Intelligence
    # ---------------------------------------------------------

    print("  Threat Intelligence:")

    alert_enrichment = enriched_iocs[alert_id]

    for ip in alert_enrichment["ips"]:
        print(
            f"    IP: "
            f"{ip['indicator']} | "
            f"{ip['classification']} | "
            f"{ip['reputation']}"
        )

    for domain in alert_enrichment["domains"]:
        print(
            f"    Domain: "
            f"{domain['indicator']} | "
            f"{domain['reputation']}"
        )

    for url in alert_enrichment["urls"]:
        print(
            f"    URL: "
            f"{url['indicator']} | "
            f"{url['reputation']}"
        )

    for file_hash in alert_enrichment["hashes"]:
        print(
            f"    Hash: "
            f"{file_hash['indicator']} | "
            f"{file_hash['reputation']}"
        )

    # ---------------------------------------------------------
    # MITRE ATT&CK
    # ---------------------------------------------------------

    print("  MITRE ATT&CK:")

    alert_mitre = mitre[alert_id]

    if alert_mitre:
        for mapping in alert_mitre:
            tactics = ", ".join(
                mapping["tactics"]
            )

            print(
                f"    {mapping['technique_id']} - "
                f"{mapping['name']}"
            )

            print(
                f"      Tactics: {tactics}"
            )
    else:
        print("    NONE")

    # ---------------------------------------------------------
    # Deterministic Investigation
    # ---------------------------------------------------------

    print("  Investigation:")

    print(
        f"    Summary: "
        f"{investigation['summary']}"
    )

    if investigation["findings"]:
        print("    Findings:")

        for finding in investigation["findings"]:
            print(
                f"      - {finding}"
            )

    print(
        f"    Recommended Action: "
        f"{investigation['recommended_action']}"
    )


def print_ai_investigation(
    alert_id,
    ai_investigation,
):
    print()
    print("  AI Investigation:")

    if not ai_investigation:
        print(
            "    Status: NOT RUN"
        )
        return

    print(
        f"    Status: "
        f"{ai_investigation['status']}"
    )

    print(
        f"    LLM Called: "
        f"{ai_investigation['llm_called']}"
    )

    if ai_investigation.get("model"):
        print(
            f"    Model: "
            f"{ai_investigation['model']}"
        )

    if ai_investigation.get("error"):
        print(
            f"    Error: "
            f"{ai_investigation['error']}"
        )

    response = ai_investigation.get(
        "response"
    )

    if response:
        print()
        print("    AI Assessment:")

        for line in response.splitlines():
            print(
                f"      {line}"
            )


def run_platform(
    run_ai_investigation=False,
):
    print_header()

    mode = (
        "FULL AI MODE"
        if run_ai_investigation
        else "DETERMINISTIC MODE"
    )

    print(
        f"Mode: {mode}"
    )

    print()

    result = process_alerts(
        ALERT_FILE,
        run_ai_investigation=run_ai_investigation,
    )

    alerts = result["alerts"]
    detections = result["detections"]
    anomalies = result["anomalies"]
    risks = result["risks"]
    iocs = result["iocs"]
    enriched_iocs = result["enriched_iocs"]
    mitre = result["mitre"]
    investigations = result["investigations"]
    ai_investigations = result[
        "ai_investigations"
    ]

    print(
        f"Alerts processed: "
        f"{len(alerts)}"
    )

    print()

    for alert in alerts:
        alert_id = alert["alert_id"]

        print("-" * 70)

        print_alert_summary(
            alert=alert,
            detections=detections,
            anomaly=anomalies,
            risk=risks,
            iocs=iocs,
            enriched_iocs=enriched_iocs,
            mitre=mitre,
            investigation=investigations[
                alert_id
            ],
        )

        print_ai_investigation(
            alert_id=alert_id,
            ai_investigation=ai_investigations.get(
                alert_id
            ),
        )

        print()

    print("=" * 70)
    print("SOC ANALYSIS COMPLETE")
    print("=" * 70)


if __name__ == "__main__":
    run_platform(
        run_ai_investigation=True
    )