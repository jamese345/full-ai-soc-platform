import unittest

from src.ingestion.alert_loader import (
    load_alerts,
    validate_alert,
    validate_alerts,
)


class TestAlertLoader(unittest.TestCase):

    def test_load_alerts(self):
        alerts = load_alerts("data/alerts/sample_alerts.json")

        self.assertEqual(len(alerts), 3)

    def test_alert_contains_required_fields(self):
        alerts = load_alerts("data/alerts/sample_alerts.json")

        self.assertTrue(validate_alert(alerts[0]))

    def test_validate_all_alerts(self):
        alerts = load_alerts("data/alerts/sample_alerts.json")

        self.assertTrue(validate_alerts(alerts))

    def test_missing_field_is_rejected(self):
        alert = {
            "alert_id": "SOC-TEST"
        }

        with self.assertRaises(ValueError):
            validate_alert(alert)


if __name__ == "__main__":
    unittest.main()