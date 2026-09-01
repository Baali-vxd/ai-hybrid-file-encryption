import numpy as np
from sklearn.ensemble import IsolationForest
import threading
from typing import Dict, Any

class ThreatDetector:
    _instance = None
    _lock = threading.Lock()

    def __init__(self):
        self.model = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        self.is_trained = False
        self._train_baseline_model()

    @classmethod
    def get_instance(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

    def _train_baseline_model(self):
        """Train IsolationForest on synthetic normal user activity baseline."""
        np.random.seed(42)

        # Generate 500 samples of normal user activity
        # Features: [failed_logins, encryption_requests, decryption_requests, failed_decryptions, access_frequency_per_min]
        normal_failed_logins = np.random.poisson(lam=0.3, size=450)
        normal_enc_reqs = np.random.randint(1, 15, size=450)
        normal_dec_reqs = np.random.randint(0, 10, size=450)
        normal_failed_dec = np.random.poisson(lam=0.1, size=450)
        normal_freq = np.random.uniform(0.5, 5.0, size=450)

        normal_data = np.column_stack((
            normal_failed_logins,
            normal_enc_reqs,
            normal_dec_reqs,
            normal_failed_dec,
            normal_freq
        ))

        # Add 50 slight variants to give model variance
        variant_data = np.random.normal(loc=[1, 5, 3, 0, 3], scale=[0.5, 2, 2, 0.2, 1], size=(50, 5))
        variant_data = np.clip(variant_data, 0, None)

        X_train = np.vstack((normal_data, variant_data))
        self.model.fit(X_train)
        self.is_trained = True

    def predict_activity(self, activity_features: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate activity feature vector:
        - failed_logins (int)
        - encryption_requests (int)
        - decryption_requests (int)
        - failed_decryptions (int)
        - access_frequency (float)
        """
        failed_logins = activity_features.get("failed_logins", 0)
        enc_reqs = activity_features.get("encryption_requests", 0)
        dec_reqs = activity_features.get("decryption_requests", 0)
        failed_dec = activity_features.get("failed_decryptions", 0)
        access_freq = activity_features.get("access_frequency", 1.0)

        feature_vector = np.array([[failed_logins, enc_reqs, dec_reqs, failed_dec, access_freq]])

        # Predict anomaly (-1 for outlier/anomalous, 1 for inlier/normal)
        raw_pred = self.model.predict(feature_vector)[0]
        # Get raw decision score (higher = normal, lower/negative = anomalous)
        anomaly_score = float(self.model.decision_function(feature_vector)[0])

        # Classification based on threshold & feature heuristics
        if failed_dec >= 3 or failed_logins >= 4 or access_freq > 15.0 or anomaly_score < -0.15:
            classification = "POTENTIAL THREAT"
            threat_level = "High"
            explanation = f"High anomaly detected! Score: {anomaly_score:.3f}. Excessive failures or rapid automated requests detected."
        elif failed_dec >= 1 or failed_logins >= 2 or access_freq > 8.0 or anomaly_score < -0.05:
            classification = "SUSPICIOUS"
            threat_level = "Medium"
            explanation = f"Moderate activity deviation. Score: {anomaly_score:.3f}. Elevated attempt count monitored."
        else:
            classification = "NORMAL"
            threat_level = "Low"
            explanation = f"User behavior matches normal patterns. Anomaly Score: {anomaly_score:.3f}."

        return {
            "classification": classification,
            "threat_level": threat_level,
            "anomaly_score": round(anomaly_score, 4),
            "is_anomaly": (raw_pred == -1),
            "explanation": explanation
        }

def get_threat_detector():
    return ThreatDetector.get_instance()
