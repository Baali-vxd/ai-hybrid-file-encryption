import datetime
from sqlalchemy.orm import Session
from backend.db.models.user import User
from backend.db.models.activity import UserActivity
from backend.ml.features import extract_feature_vector
from backend.ml.detector import get_threat_detector
from backend.core.logging import log_security_event

def get_user_threat_status(db: Session, user: User) -> dict:
    """Evaluate real-time behavioral features and return IsolationForest threat assessment."""
    activity = db.query(UserActivity).filter(UserActivity.user_id == user.id).first()
    if not activity:
        activity = UserActivity(user_id=user.id)
        db.add(activity)
        db.commit()

    features = extract_feature_vector(activity)
    detector = get_threat_detector()
    assessment = detector.predict_activity(features)

    return {
        "user_id": user.id,
        "username": user.username,
        "status": assessment["classification"],
        "threat_level": assessment["threat_level"],
        "anomaly_score": assessment["anomaly_score"],
        "failed_logins": activity.failed_logins,
        "encryption_requests": activity.encryption_requests,
        "decryption_requests": activity.decryption_requests,
        "failed_decryptions": activity.failed_decryptions,
        "access_frequency": features["access_frequency"],
        "explanation": assessment["explanation"]
    }

def simulate_attack_event(db: Session, user: User, attack_type: str) -> dict:
    """Simulate attack behaviors for viva demo and evaluation."""
    activity = db.query(UserActivity).filter(UserActivity.user_id == user.id).first()
    if not activity:
        activity = UserActivity(user_id=user.id)
        db.add(activity)

    if attack_type == "brute_force":
        activity.failed_logins += 4
        details = "Simulated brute-force login attack (4 consecutive failed attempts)"
    elif attack_type == "burst_request":
        activity.decryption_requests += 25
        details = "Simulated high-frequency automated request burst (25 rapid requests)"
    elif attack_type == "invalid_keys":
        activity.failed_decryptions += 3
        details = "Simulated invalid RSA key decryption attempt (3 failed unwrap attempts)"
    else:
        activity.failed_decryptions += 2
        details = f"Simulated security attack scenario: {attack_type}"

    activity.last_access_timestamp = datetime.datetime.utcnow()
    db.commit()

    features = extract_feature_vector(activity)
    detector = get_threat_detector()
    assessment = detector.predict_activity(features)

    log_security_event(
        db=db,
        activity_type="ATTACK_SIMULATION",
        status="TRIGGERED",
        threat_level=assessment["threat_level"],
        anomaly_score=assessment["anomaly_score"],
        details=details,
        user_id=user.id,
        username=user.username
    )

    return {
        "message": f"Attack simulation '{attack_type}' executed",
        "new_status": assessment["classification"],
        "threat_level": assessment["threat_level"],
        "anomaly_score": assessment["anomaly_score"],
        "details": details
    }

def reset_user_simulation(db: Session, user: User) -> dict:
    """Reset user activity counters to baseline state."""
    activity = db.query(UserActivity).filter(UserActivity.user_id == user.id).first()
    if activity:
        activity.login_attempts = 0
        activity.failed_logins = 0
        activity.failed_decryptions = 0
        activity.decryption_requests = 0
        activity.encryption_requests = 0
        activity.last_access_timestamp = datetime.datetime.utcnow() - datetime.timedelta(minutes=10)
        db.commit()

    log_security_event(
        db=db,
        activity_type="ATTACK_SIMULATION_RESET",
        status="SUCCESS",
        threat_level="Low",
        anomaly_score=0.0,
        details="Reset behavioral counters to baseline normal state",
        user_id=user.id,
        username=user.username
    )

    return {"message": "User threat counters reset to baseline normal state"}
