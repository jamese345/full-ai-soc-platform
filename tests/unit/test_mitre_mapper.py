import unittest

from src.mitre.mapper import (
    MitreMapper,
)


class TestMitreMapper(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.mapper = MitreMapper()
        cls.mapper.load()

    def test_dataset_loads(self):
        self.assertGreater(
            len(self.mapper.techniques),
            0,
        )

    def test_brute_force_maps_to_t1110(self):
        detection = {
            "alert_id": "SOC-0001",
            "detection": "BRUTE_FORCE",
        }

        result = self.mapper.map_detection(
            detection
        )

        self.assertIsNotNone(result)

        self.assertEqual(
            result["technique_id"],
            "T1110",
        )

        self.assertEqual(
            result["name"],
            "Brute Force",
        )

    def test_suspicious_login_maps_to_t1078(self):
        detection = {
            "alert_id": "SOC-0001",
            "detection": "SUSPICIOUS_LOGIN",
        }

        result = self.mapper.map_detection(
            detection
        )

        self.assertIsNotNone(result)

        self.assertEqual(
            result["technique_id"],
            "T1078",
        )

        self.assertEqual(
            result["name"],
            "Valid Accounts",
        )

    def test_unknown_detection_returns_none(self):
        detection = {
            "alert_id": "SOC-0001",
            "detection": "UNKNOWN_DETECTION",
        }

        result = self.mapper.map_detection(
            detection
        )

        self.assertIsNone(result)

    def test_multiple_detections(self):
        detections = [
            {
                "alert_id": "SOC-0001",
                "detection": "BRUTE_FORCE",
            },
            {
                "alert_id": "SOC-0001",
                "detection": "SUSPICIOUS_LOGIN",
            },
        ]

        results = self.mapper.map_detections(
            detections
        )

        self.assertEqual(
            len(results),
            2,
        )


if __name__ == "__main__":
    unittest.main()