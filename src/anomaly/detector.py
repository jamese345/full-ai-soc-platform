from pathlib import Path

import joblib
import pandas as pd

from src.anomaly.features import extract_features


FEATURES = [
    "failed_attempts",
    "successful_logins",
    "login_frequency",
    "unique_source_ips",
    "login_hour",
    "session_duration",
    "request_count",
]


class AnomalyDetector:
    """Isolation Forest anomaly detector for SOC alerts."""

    def __init__(self, model_path: str):
        self.model_path = Path(model_path)
        self.model = None

    def load_model(self):
        """Load the trained Isolation Forest model."""

        if not self.model_path.exists():
            raise FileNotFoundError(
                f"Anomaly model not found: {self.model_path}"
            )

        self.model = joblib.load(self.model_path)

    def predict(self, alert: dict) -> dict:
        """Generate an anomaly prediction for one alert."""

        if self.model is None:
            self.load_model()

        feature_data = extract_features(alert)

        features = pd.DataFrame(
            [[feature_data[feature] for feature in FEATURES]],
            columns=FEATURES,
        )

        prediction = self.model.predict(features)[0]
        score = self.model.decision_function(features)[0]

        is_anomaly = prediction == -1

        return {
            "is_anomaly": bool(is_anomaly),
            "anomaly_score": float(score),
            "classification": (
                "ANOMALY"
                if is_anomaly
                else "NORMAL"
            ),
        }