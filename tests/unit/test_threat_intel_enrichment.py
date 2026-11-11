import unittest

from src.threat_intel.enrichment import (
    classify_ip,
    enrich_ip,
    enrich_iocs,
)


class TestThreatIntelEnrichment(unittest.TestCase):

    def test_private_ip_classification(self):
        result = classify_ip("192.168.1.50")

        self.assertEqual(
            result,
            "PRIVATE",
        )

    def test_public_ip_classification(self):
        result = classify_ip("8.8.8.8")

        self.assertEqual(
            result,
            "PUBLIC",
        )

    def test_invalid_ip_classification(self):
        result = classify_ip("not-an-ip")

        self.assertEqual(
            result,
            "INVALID",
        )

    def test_private_ip_enrichment(self):
        result = enrich_ip("192.168.1.50")

        self.assertEqual(
            result["classification"],
            "PRIVATE",
        )

        self.assertEqual(
            result["reputation"],
            "INTERNAL",
        )

    def test_public_ip_enrichment(self):
        result = enrich_ip("8.8.8.8")

        self.assertEqual(
            result["classification"],
            "PUBLIC",
        )

        self.assertEqual(
            result["reputation"],
            "UNKNOWN",
        )

    def test_ioc_enrichment(self):
        iocs = {
            "ips": ["192.168.1.50"],
            "domains": ["malicious-example.com"],
            "urls": [],
            "hashes": [],
        }

        result = enrich_iocs(iocs)

        self.assertEqual(
            len(result["ips"]),
            1,
        )

        self.assertEqual(
            result["ips"][0]["classification"],
            "PRIVATE",
        )

        self.assertEqual(
            result["domains"][0]["indicator"],
            "malicious-example.com",
        )


if __name__ == "__main__":
    unittest.main()