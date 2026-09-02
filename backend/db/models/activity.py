import datetime
from sqlalchemy import Column, Integer, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from backend.db.database import Base

class UserActivity(Base):
    __tablename__ = "user_activity"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), unique=True, nullable=False)
    login_attempts = Column(Integer, default=0)
    failed_logins = Column(Integer, default=0)
    encryption_requests = Column(Integer, default=0)
    decryption_requests = Column(Integer, default=0)
    failed_decryptions = Column(Integer, default=0)
    last_access_timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    user = relationship("User", back_populates="activity")
