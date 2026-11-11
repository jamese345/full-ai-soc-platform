from src.ingestion.alert_loader import (
    load_alerts,
    validate_alerts,
)
from src.ingestion.normalizer import normalize_alert
from src.detection.engine import detect_alerts
from src.anomaly.detector import AnomalyDetector
from src.triage.risk_engine import assess_risk
from src.threat_intel.ioc_extractor import extract_iocs
from src.threat_intel.enrichment import enrich_iocs
from src.mitre.mapper import MitreMapper
from src.investigation.investigator import build_investigation
from src.ai.investigation_agent import InvestigationAgent
from src.cases.case_manager import CaseManager
from src.reporting.report_generator import SOCReportGenerator

MODEL_PATH = "models/isolation_forest.joblib"


def process_alerts(
    file_path: str,
    run_ai_investigation: bool = False,
) -> dict:
    """
    Process alerts through the complete SOC pipeline.

    The deterministic security pipeline always runs.

    AI investigation is optional so that:
    - automated tests do not require an API key,
    - offline analysis remains possible,
    - API usage is explicitly controlled.
    """

    # ---------------------------------------------------------
    # 1. Load and validate alerts
    # ---------------------------------------------------------

    alerts = load_alerts(file_path)
    validate_alerts(alerts)

    # ---------------------------------------------------------
    # 2. Normalize alerts
    # ---------------------------------------------------------

    normalized_alerts = [
        normalize_alert(alert)
        for alert in alerts
    ]

    # ---------------------------------------------------------
    # 3. Rule-based detection
    # ---------------------------------------------------------

    detections = detect_alerts(
        normalized_alerts
    )

    # ---------------------------------------------------------
    # 4. ML anomaly detection
    # ---------------------------------------------------------

    anomaly_detector = AnomalyDetector(
        MODEL_PATH
    )

    anomalies = {}

    for alert in normalized_alerts:
        alert_id = alert["alert_id"]

        anomalies[alert_id] = (
            anomaly_detector.predict(alert)
        )

    # ---------------------------------------------------------
    # 5. Risk assessment
    # ---------------------------------------------------------

    risks = {}

    for alert in normalized_alerts:
        alert_id = alert["alert_id"]

        risks[alert_id] = assess_risk(
            alert=alert,
            detections=detections[alert_id],
            anomaly=anomalies[alert_id],
        )

    # ---------------------------------------------------------
    # 6. IOC extraction + enrichment
    # ---------------------------------------------------------

    iocs = {}
    enriched_iocs = {}

    for alert in normalized_alerts:
        alert_id = alert["alert_id"]

        extracted_iocs = extract_iocs(
            alert["description"]
        )

        iocs[alert_id] = extracted_iocs

        enriched_iocs[alert_id] = enrich_iocs(
            extracted_iocs
        )

    # ---------------------------------------------------------
    # 7. MITRE ATT&CK mapping
    # ---------------------------------------------------------

    mitre_mapper = MitreMapper()

    mitre_mappings = {}

    for alert in normalized_alerts:
        alert_id = alert["alert_id"]

        mitre_mappings[alert_id] = (
            mitre_mapper.map_detections(
                detections[alert_id]
            )
        )

    # ---------------------------------------------------------
    # 8. Deterministic investigation
    # ---------------------------------------------------------

    investigations = {}

    for alert in normalized_alerts:
        alert_id = alert["alert_id"]

        investigations[alert_id] = (
            build_investigation(
                alert=alert,
                detections=detections[alert_id],
                anomaly=anomalies[alert_id],
                risk=risks[alert_id],
                iocs=iocs[alert_id],
                enriched_iocs=enriched_iocs[alert_id],
                mitre=mitre_mappings[alert_id],
            )
        )

    # ---------------------------------------------------------
    # 9. AI investigation
    # ---------------------------------------------------------

    ai_investigations = {}

    if run_ai_investigation:
        investigation_agent = InvestigationAgent()

        for alert in normalized_alerts:
            alert_id = alert["alert_id"]

            ai_investigations[alert_id] = (
                investigation_agent.investigate_with_llm(
                    alert=alert,
                    detections=detections[alert_id],
                    anomaly=anomalies[alert_id],
                    risk=risks[alert_id],
                    iocs=iocs[alert_id],
                    enriched_iocs=enriched_iocs[alert_id],
                    mitre=mitre_mappings[alert_id],
                )
            )

    cases = {}

    case_manager = CaseManager()

    for alert in normalized_alerts:
        alert_id = alert["alert_id"]

        cases[alert_id] = case_manager.create_case(
            alert=alert,
            investigation=investigations[alert_id],
            risk=risks[alert_id],
            ai_investigation=ai_investigations.get(
                alert_id
            ),
        )

    reports = {}
    report_paths = {}

    report_generator = SOCReportGenerator()

    for alert in normalized_alerts:
        alert_id = alert["alert_id"]

        report, report_path = (
            report_generator.generate_and_save_report(
                cases[alert_id]
            )
        )

        reports[alert_id] = report
        report_paths[alert_id] = str(
            report_path
        )
    # ---------------------------------------------------------
    # 10. Return complete SOC results
    # ---------------------------------------------------------

    return {
        "alerts": normalized_alerts,
        "detections": detections,
        "anomalies": anomalies,
        "risks": risks,
        "iocs": iocs,
        "enriched_iocs": enriched_iocs,
        "mitre": mitre_mappings,
        "investigations": investigations,
        "ai_investigations": ai_investigations,
        "cases": cases,
        "reports": reports,
        "report_paths": report_paths,
    }