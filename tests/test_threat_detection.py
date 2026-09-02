from backend.ml.detector import get_threat_detector

def test_isolation_forest_normal_behavior():
    detector = get_threat_detector()
    features = {
        "failed_logins": 0,
        "encryption_requests": 3,
        "decryption_requests": 2,
        "failed_decryptions": 0,
        "access_frequency": 2.0
    }
    res = detector.predict_activity(features)
    assert res["classification"] == "NORMAL"
    assert res["threat_level"] == "Low"

def test_isolation_forest_threat_behavior():
    detector = get_threat_detector()
    features = {
        "failed_logins": 5,
        "encryption_requests": 1,
        "decryption_requests": 30,
        "failed_decryptions": 4,
        "access_frequency": 20.0
    }
    res = detector.predict_activity(features)
    assert res["classification"] == "POTENTIAL THREAT"
    assert res["threat_level"] == "High"
