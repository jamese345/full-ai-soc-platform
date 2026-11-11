import unittest

from src.pipeline import process_alerts


class TestPipeline(unittest.TestCase):

    def setUp(self):
        self.result = process_alerts(
            "data/alerts/sample_alerts.json"
        )

    def test_process_alerts(self):
        alerts = self.result["alerts"]

        self.assertEqual(len(alerts), 3)

    def test_pipeline_returns_normalized_alerts(self):
        alerts = self.result["alerts"]

        for alert in alerts:
            self.assertIn("alert_id", alert)
            self.assertIn("severity", alert)
            self.assertIn("timestamp", alert)

    def test_pipeline_returns_detections(self):
        detections = self.result["detections"]

        self.assertEqual(len(detections), 3)

    def test_brute_force_alert_detected(self):
        detections = self.result["detections"]

        alert_detections = detections["SOC-0001"]

        detection_names = {
            detection["detection"]
            for detection in alert_detections
        }

        self.assertIn(
            "BRUTE_FORCE",
            detection_names,
        )

    def test_suspicious_request_detected(self):
        detections = self.result["detections"]

        alert_detections = detections["SOC-0002"]

        detection_names = {
            detection["detection"]
            for detection in alert_detections
        }

        self.assertIn(
            "SUSPICIOUS_REQUEST",
            detection_names,
        )

    def test_pipeline_returns_anomalies(self):
        anomalies = self.result["anomalies"]

        self.assertEqual(len(anomalies), 3)

    def test_anomaly_result_contains_required_fields(self):
        anomalies = self.result["anomalies"]

        for result in anomalies.values():
            self.assertIn("is_anomaly", result)
            self.assertIn("anomaly_score", result)
            self.assertIn("classification", result)

    def test_pipeline_returns_iocs(self):
        iocs = self.result["iocs"]

        self.assertEqual(
            len(iocs),
            3,
        )


    def test_iocs_are_extracted_from_alerts(self):
        iocs = self.result["iocs"]

        self.assertIn(
            "192.168.1.50",
            iocs["SOC-0001"]["ips"],
        )

        self.assertIn(
            "malicious-example.com",
            iocs["SOC-0002"]["domains"],
        )

    def test_pipeline_returns_enriched_iocs(self):
        enriched_iocs = self.result["enriched_iocs"]

        self.assertEqual(
            len(enriched_iocs),
            3,
        )


    def test_private_ip_is_classified(self):
        enriched_iocs = self.result["enriched_iocs"]

        soc_0001 = enriched_iocs["SOC-0001"]

        self.assertEqual(
            soc_0001["ips"][0]["classification"],
            "PRIVATE",
        )

        self.assertEqual(
            soc_0001["ips"][0]["reputation"],
            "INTERNAL",
        )


    def test_domain_enrichment(self):
        enriched_iocs = self.result["enriched_iocs"]

        soc_0002 = enriched_iocs["SOC-0002"]

        self.assertEqual(
            soc_0002["domains"][0]["indicator"],
            "malicious-example.com",
        )

        self.assertEqual(
            soc_0002["domains"][0]["source"],
            "LOCAL",
        )
        
    def test_pipeline_returns_mitre_mappings(self):
        mitre = self.result["mitre"]

        self.assertEqual(
            len(mitre),
            3,
        )


    def test_brute_force_maps_to_mitre(self):
        mitre = self.result["mitre"]

        mappings = mitre["SOC-0001"]

        technique_ids = [
            mapping["technique_id"]
            for mapping in mappings
        ]

        self.assertIn(
            "T1110",
            technique_ids,
        )


    def test_suspicious_login_maps_to_mitre(self):
        mitre = self.result["mitre"]

        mappings = mitre["SOC-0001"]

        technique_ids = [
            mapping["technique_id"]
            for mapping in mappings
        ]

        self.assertIn(
            "T1078",
            technique_ids,
        )

    def test_pipeline_returns_investigations(self):
        investigations = self.result[
            "investigations"
        ]

        self.assertEqual(
            len(investigations),
            3,
        )


    def test_investigation_contains_alert_id(self):
        investigations = self.result[
            "investigations"
        ]

        self.assertEqual(
            investigations["SOC-0001"]["alert_id"],
            "SOC-0001",
        )


    def test_critical_alert_has_escalation_action(self):
        investigations = self.result[
            "investigations"
        ]

        self.assertEqual(
            investigations["SOC-0001"][
                "recommended_action"
            ],
            "ESCALATE",
        )


if __name__ == "__main__":
    unittest.main()