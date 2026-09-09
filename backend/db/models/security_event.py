import datetime
from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey, Text
from backend.db.database import Base

class SecurityLog(Base):
    __tablename__ = "security_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    username = Column(String(50), nullable=True)
    activity_type = Column(String(100), nullable=False)
    status = Column(String(50), nullable=False)
    threat_level = Column(String(20), nullable=False)  # Low, Medium, High
    anomaly_score = Column(Float, default=0.0)
    details = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)
