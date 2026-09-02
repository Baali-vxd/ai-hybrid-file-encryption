import logging
from typing import Optional
from sqlalchemy.orm import Session
from backend.db.models.security_event import SecurityLog

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

logger = logging.getLogger("cns_security")

def log_security_event(
    db: Session,
    activity_type: str,
    status: str,
    threat_level: str,
    anomaly_score: float = 0.0,
    details: Optional[str] = None,
    user_id: Optional[int] = None,
    username: Optional[str] = None
) -> SecurityLog:
    """Persist security event audit log entry in DB and output to system logger."""
    logger.info(f"SECURITY_LOG: [{threat_level}] {activity_type} - {status} | User: {username or 'System'} | Score: {anomaly_score:.3f} | Details: {details or ''}")
    log_entry = SecurityLog(
        user_id=user_id,
        username=username,
        activity_type=activity_type,
        status=status,
        threat_level=threat_level,
        anomaly_score=anomaly_score,
        details=details
    )
    db.add(log_entry)
    db.commit()
    db.refresh(log_entry)
    return log_entry
