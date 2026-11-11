from pathlib import Path

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest


FEATURES = [
    "failed_attempts",
    "successful_logins",
    "login_frequency",
    "unique_source_ips",
    "login_hour",
    "session_duration",
    "request_count",
]


def generate_training_data(
    normal_samples: int = 1000,
    anomaly_samples: int = 100,
    random_state: int = 42,
) -> pd.DataFrame:

    normal = pd.DataFrame({
        "failed_attempts": pd.Series(
            __import__("numpy").random.default_rng(random_state).integers(
                0, 4, normal_samples
            )
        ),
        "successful_logins": 1,
        "login_frequency": __import__("numpy").random.default_rng(
            random_state + 1
        ).integers(1, 5, normal_samples),
        "unique_source_ips": 1,
        "login_hour": __import__("numpy").random.default_rng(
            random_state + 2
        ).integers(7, 19, normal_samples),
        "session_duration": __import__("numpy").random.default_rng(
            random_state + 3
        ).integers(60, 301, normal_samples),
        "request_count": __import__("numpy").random.default_rng(
            random_state + 4
        ).integers(5, 51, normal_samples),
    })

    rng = __import__("numpy").random.default_rng(random_state + 10)

    anomalies = pd.DataFrame({
        "failed_attempts": rng.integers(15, 70, anomaly_samples),
        "successful_logins": rng.integers(1, 4, anomaly_samples),
        "login_frequency": rng.integers(15, 40, anomaly_samples),
        "unique_source_ips": rng.integers(4, 10, anomaly_samples),
        "login_hour": rng.integers(0, 5, anomaly_samples),
        "session_duration": rng.integers(5, 40, anomaly_samples),
        "request_count": rng.integers(150, 500, anomaly_samples),
    })

    data = pd.concat(
        [normal, anomalies],
        ignore_index=True,
    )

    return data[FEATURES]


def train_model(data_path: str, model_path: str):

    data = pd.read_csv(data_path)

    X = data[FEATURES]

    model = IsolationForest(
        n_estimators=200,
        contamination=0.10,
        random_state=42,
    )

    model.fit(X)

    output_path = Path(model_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(model, output_path)

    print(f"Training samples: {len(data)}")
    print(f"Features: {len(FEATURES)}")
    print(f"Model saved to: {output_path}")


if __name__ == "__main__":
    data_path = "data/alerts/training_alerts.csv"

    generated_data = generate_training_data()

    generated_data.to_csv(
        data_path,
        index=False,
    )

    print(f"Generated training dataset: {data_path}")

    train_model(
        data_path,
        "models/isolation_forest.joblib",
    )