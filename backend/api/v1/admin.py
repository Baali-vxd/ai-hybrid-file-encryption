from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.db.database import get_db
from backend.db.models.user import User
from backend.db.models.file import FileRecord
from backend.schemas.auth_schemas import UserResponse
from backend.schemas.file_schemas import FileRecordResponse
from backend.services.auth_service import require_role

router = APIRouter(prefix="/admin", tags=["Admin Management (RBAC)"])

@router.get("/users", response_model=List[UserResponse])
def get_all_users(admin: User = Depends(require_role("ADMIN")), db: Session = Depends(get_db)):
    return db.query(User).all()

@router.get("/files", response_model=List[FileRecordResponse])
def get_all_files(admin: User = Depends(require_role("ADMIN")), db: Session = Depends(get_db)):
    return db.query(FileRecord).order_by(FileRecord.encryption_timestamp.desc()).all()
