from sqlalchemy.orm import Session
from backend.models import SecurityLog, UserActivity
import datetime

def log_security_event(
    db: Session,
    activity_type: str,
    status: str,
    threat_level: str,
    user_id: int = None,
    username: str = None,
    anomaly_score: float = 0.0,
    details: str = ""
):
    """Save security log entry to database."""
    log_entry = SecurityLog(
        user_id=user_id,
        username=username,
        activity_type=activity_type,
        status=status,
        threat_level=threat_level,
        anomaly_score=anomaly_score,
        details=details,
        timestamp=datetime.datetime.utcnow()
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry

def get_or_create_user_activity(db: Session, user_id: int) -> UserActivity:
    """Fetch or initialize UserActivity counters for a user."""
    activity = db.query(UserActivity).filter(UserActivity.user_id == user_id).first()
    if not activity:
        activity = UserActivity(user_id=user_id)
        db.add(activity)
        db.commit()
        db.refresh(activity)
    return activity
