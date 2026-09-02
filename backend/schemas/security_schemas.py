import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict

class SecurityLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: Optional[int] = None
    username: Optional[str] = None
    activity_type: str
    status: str
    threat_level: str
    anomaly_score: float
    details: Optional[str] = None
    timestamp: datetime.datetime

class ThreatStatusResponse(BaseModel):
    user_id: int
    username: str
    status: str
    threat_level: str
    anomaly_score: float
    failed_logins: int
    encryption_requests: int
    decryption_requests: int
    failed_decryptions: int
    access_frequency: float
    explanation: str
