from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from backend.db.database import get_db
from backend.db.models.user import User
from backend.schemas.auth_schemas import UserRegisterRequest, UserLoginRequest, TokenResponse, UserResponse
from backend.services.auth_service import register_user, authenticate_user, get_current_user

router = APIRouter(prefix="/auth", tags=["Authentication"])

@router.post("/register", response_model=UserResponse)
def register(req: UserRegisterRequest, db: Session = Depends(get_db)):
    return register_user(db, username=req.username, email=req.email, password=req.password)

@router.post("/login", response_model=TokenResponse)
def login(req: UserLoginRequest, db: Session = Depends(get_db)):
    result = authenticate_user(db, username=req.username, password=req.password)
    return {"access_token": result["access_token"], "token_type": "bearer"}

@router.get("/me", response_model=UserResponse)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user
