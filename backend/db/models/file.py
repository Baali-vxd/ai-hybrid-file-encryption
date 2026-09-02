import datetime
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import relationship
from backend.db.database import Base

class FileRecord(Base):
    __tablename__ = "files"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    original_filename = Column(String(255), nullable=False)
    encrypted_filename = Column(String(255), nullable=False)
    encrypted_aes_key = Column(Text, nullable=False)  # Base64 encoded RSA-encrypted AES key
    sha256_hash = Column(String(64), nullable=False)   # Checksum of original file
    file_size = Column(Integer, default=0)
    encryption_algorithm = Column(String(50), default="AES-256-GCM")
    key_algorithm = Column(String(50), default="RSA-2048-OAEP")
    encryption_timestamp = Column(DateTime, default=datetime.datetime.utcnow)

    owner = relationship("User", back_populates="files")
