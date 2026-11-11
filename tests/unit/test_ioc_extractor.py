import unittest

from src.threat_intel.ioc_extractor import (
    extract_ips,
    extract_domains,
    extract_urls,
    extract_hashes,
    extract_iocs,
)


class TestIOCExtractor(unittest.TestCase):

    def test_extract_ip(self):
        text = "Connection from 192.168.1.50"

        result = extract_ips(text)

        self.assertEqual(
            result,
            ["192.168.1.50"],
        )

    def test_extract_multiple_ips(self):
        text = (
            "Traffic from 192.168.1.50 "
            "and 10.10.10.25"
        )

        result = extract_ips(text)

        self.assertEqual(
            set(result),
            {
                "192.168.1.50",
                "10.10.10.25",
            },
        )

    def test_extract_domain(self):
        text = "Connection to malicious-example.com"

        result = extract_domains(text)

        self.assertIn(
            "malicious-example.com",
            result,
        )

    def test_extract_url(self):
        text = (
            "User visited "
            "https://malicious-example.com/login"
        )

        result = extract_urls(text)

        self.assertEqual(
            result,
            [
                "https://malicious-example.com/login"
            ],
        )

    def test_extract_md5(self):
        text = (
            "File hash: "
            "d41d8cd98f00b204e9800998ecf8427e"
        )

        result = extract_hashes(text)

        self.assertIn(
            "d41d8cd98f00b204e9800998ecf8427e",
            result,
        )

    def test_extract_sha256(self):
        sha256 = (
            "a" * 64
        )

        result = extract_hashes(
            f"Hash: {sha256}"
        )

        self.assertIn(
            sha256,
            result,
        )

    def test_extract_all_iocs(self):
        text = (
            "Connection from 192.168.1.50 "
            "to malicious-example.com "
            "using https://malicious-example.com/login "
            "with hash "
            "d41d8cd98f00b204e9800998ecf8427e"
        )

        result = extract_iocs(text)

        self.assertIn(
            "192.168.1.50",
            result["ips"],
        )

        self.assertIn(
            "malicious-example.com",
            result["domains"],
        )

        self.assertIn(
            "https://malicious-example.com/login",
            result["urls"],
        )

        self.assertIn(
            "d41d8cd98f00b204e9800998ecf8427e",
            result["hashes"],
        )

    def test_duplicate_iocs_are_removed(self):
        text = (
            "192.168.1.50 "
            "192.168.1.50 "
            "192.168.1.50"
        )

        result = extract_iocs(text)

        self.assertEqual(
            result["ips"],
            ["192.168.1.50"],
        )


if __name__ == "__main__":
    unittest.main()