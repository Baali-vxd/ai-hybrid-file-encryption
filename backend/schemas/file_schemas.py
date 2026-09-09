import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict

class FileRecordResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    original_filename: str
    encrypted_filename: str
    sha256_hash: str
    file_size: int
    encryption_algorithm: str
    key_algorithm: str
    encryption_timestamp: datetime.datetime

class DecryptionResponse(BaseModel):
    status: str
    message: str
    anomaly_score: float
    threat_level: str
    original_hash: str
    computed_hash: str
    integrity_verified: bool
    download_url: Optional[str] = None
