from pydantic import BaseModel, EmailStr
from typing import Optional, List
from datetime import datetime

class UserRegister(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    username: str

class UserOut(BaseModel):
    id: int
    username: str
    email: str
    created_at: datetime

    class Config:
        from_attributes = True

class FileRecordOut(BaseModel):
    id: int
    original_filename: str
    encrypted_filename: str
    sha256_hash: str
    file_size: int
    encryption_timestamp: datetime

    class Config:
        from_attributes = True

class DecryptResponse(BaseModel):
    status: str  # SUCCESS or INTEGRITY_FAILED or BLOCKED
    integrity_verified: bool
    message: str
    original_filename: str
    original_hash: str
    computed_hash: str
    download_url: Optional[str] = None
    anomaly_score: float
    threat_level: str

class ThreatStatusResponse(BaseModel):
    status: str  # NORMAL, SUSPICIOUS, POTENTIAL THREAT
    anomaly_score: float
    threat_level: str
    failed_logins: int
    encryption_requests: int
    decryption_requests: int
    failed_decryptions: int
    explanation: str

class SecurityLogOut(BaseModel):
    id: int
    timestamp: datetime
    username: Optional[str]
    activity_type: str
    status: str
    threat_level: str
    anomaly_score: float
    details: Optional[str]

    class Config:
        from_attributes = True

class DashboardStatsResponse(BaseModel):
    total_users: int
    total_files_encrypted: int
    total_files_decrypted: int
    normal_activities: int
    suspicious_activities: int
    threat_alerts: int
    threat_level_distribution: dict
    activity_over_time: List[dict]
