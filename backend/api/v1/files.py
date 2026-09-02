import os
from typing import List
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from backend.core.config import settings
from backend.db.database import get_db
from backend.db.models.user import User
from backend.db.models.file import FileRecord
from backend.schemas.file_schemas import FileRecordResponse, DecryptionResponse
from backend.services.auth_service import get_current_user
from backend.services.file_service import process_file_encryption, process_file_decryption

router = APIRouter(prefix="/files", tags=["Files & Cryptography"])

@router.post("/encrypt", response_model=FileRecordResponse)
async def encrypt_file(file: UploadFile = File(...), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")
    return process_file_encryption(db, current_user, file_bytes, file.filename)

@router.get("", response_model=List[FileRecordResponse])
def list_files(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role.upper() == "ADMIN":
        return db.query(FileRecord).order_by(FileRecord.encryption_timestamp.desc()).all()
    return db.query(FileRecord).filter(FileRecord.user_id == current_user.id).order_by(FileRecord.encryption_timestamp.desc()).all()

@router.post("/{file_id}/decrypt", response_model=DecryptionResponse)
def decrypt_file(file_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return process_file_decryption(db, current_user, file_id)

@router.get("/download/{filename}")
def download_decrypted_file(filename: str):
    file_path = os.path.join(settings.STORAGE_DECRYPTED_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File expired or not found")
    return FileResponse(file_path, filename=filename, media_type="application/octet-stream")
