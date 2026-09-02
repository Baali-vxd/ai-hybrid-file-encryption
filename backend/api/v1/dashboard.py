from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func
from backend.db.database import get_db
from backend.db.models.user import User
from backend.db.models.file import FileRecord
from backend.db.models.security_event import SecurityLog

router = APIRouter(prefix="/dashboard", tags=["Dashboard & Telemetry"])

@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    total_users = db.query(User).count()
    total_files_encrypted = db.query(FileRecord).count()
    total_files_decrypted = db.query(SecurityLog).filter(
        SecurityLog.activity_type == "FILE_DECRYPTION",
        SecurityLog.status == "SUCCESS"
    ).count()

    normal_acts = db.query(SecurityLog).filter(SecurityLog.threat_level == "Low").count()
    suspicious_acts = db.query(SecurityLog).filter(SecurityLog.threat_level == "Medium").count()
    threat_alerts = db.query(SecurityLog).filter(SecurityLog.threat_level == "High").count()

    # Activity Timeline telemetry
    recent_logs = db.query(SecurityLog).order_by(SecurityLog.timestamp.desc()).limit(10).all()
    recent_logs.reverse()

    timeline_data = []
    for log in recent_logs:
        timeline_data.append({
            "timestamp": log.timestamp.strftime("%H:%M:%S"),
            "score": log.anomaly_score
        })

    if not timeline_data:
        timeline_data = [
            {"timestamp": "12:00", "score": 0.12},
            {"timestamp": "12:05", "score": 0.08},
            {"timestamp": "12:10", "score": 0.15}
        ]

    return {
        "total_users": total_users,
        "total_files_encrypted": total_files_encrypted,
        "total_files_decrypted": total_files_decrypted,
        "normal_activities": normal_acts,
        "suspicious_activities": suspicious_acts,
        "threat_alerts": threat_alerts,
        "threat_level_distribution": {
            "Low": normal_acts or 1,
            "Medium": suspicious_acts,
            "High": threat_alerts
        },
        "activity_over_time": timeline_data
    }
