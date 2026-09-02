from typing import Optional, List
from sqlalchemy.orm import Session
from sqlalchemy import desc
from backend.db.models.security_event import SecurityLog

def fetch_security_logs(
    db: Session,
    threat_level: Optional[str] = None,
    search: Optional[str] = None,
    limit: int = 50
) -> List[SecurityLog]:
    """Retrieve security audit logs with filtering by threat level and search query."""
    query = db.query(SecurityLog)

    if threat_level and threat_level != "All":
        query = query.filter(SecurityLog.threat_level == threat_level)

    if search:
        pattern = f"%{search}%"
        query = query.filter(
            (SecurityLog.username.like(pattern)) |
            (SecurityLog.activity_type.like(pattern)) |
            (SecurityLog.details.like(pattern))
        )

    return query.order_by(desc(SecurityLog.timestamp)).limit(limit).all()
