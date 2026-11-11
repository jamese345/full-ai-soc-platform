import unittest

from src.anomaly.detector import AnomalyDetector


MODEL_PATH = "models/isolation_forest.joblib"


class TestAnomalyDetector(unittest.TestCase):

    def setUp(self):
        self.detector = AnomalyDetector(MODEL_PATH)

    def test_model_loads(self):
        self.detector.load_model()

        self.assertIsNotNone(self.detector.model)

    def test_prediction_contains_required_fields(self):
        alert = {
            "failed_attempts": 20,
            "successful_logins": 1,
        }

        result = self.detector.predict(alert)

        self.assertIn("is_anomaly", result)
        self.assertIn("anomaly_score", result)
        self.assertIn("classification", result)

    def test_prediction_classification(self):
        alert = {
            "failed_attempts": 20,
            "successful_logins": 1,
        }

        result = self.detector.predict(alert)

        self.assertIn(
            result["classification"],
            {"ANOMALY", "NORMAL"},
        )


if __name__ == "__main__":
    unittest.main()