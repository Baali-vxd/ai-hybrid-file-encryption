import datetime
from sqlalchemy import Column, Integer, String, DateTime, Float, ForeignKey, Text
from sqlalchemy.orm import relationship
from backend.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    files = relationship("FileRecord", back_populates="owner")
    activity = relationship("UserActivity", back_populates="user", uselist=False)

class FileRecord(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    original_filename = Column(String(255), nullable=False)
    encrypted_filename = Column(String(255), nullable=False)
    encrypted_aes_key = Column(Text, nullable=False)  # Base64 encoded RSA-encrypted AES key
    sha256_hash = Column(String(64), nullable=False)   # Checksum of original file
    file_size = Column(Integer, default=0)
    encryption_timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    owner = relationship("User", back_populates="files")

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
