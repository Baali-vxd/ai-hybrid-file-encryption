import datetime
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from backend.db.database import get_db
from backend.db.models.user import User
from backend.db.models.activity import UserActivity
from backend.core.security import verify_password, get_password_hash, create_access_token, decode_access_token
from backend.core.logging import log_security_event

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login")

def register_user(db: Session, username: str, email: str, password: str, role: str = "USER") -> User:
    """Register new user account and initialize activity tracking record."""
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(status_code=400, detail="Username already registered")
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        username=username,
        email=email,
        password_hash=get_password_hash(password),
        role=role.upper()
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # Initialize activity record
    activity = UserActivity(user_id=user.id)
    db.add(activity)
    db.commit()

    log_security_event(
        db=db,
        activity_type="USER_REGISTER",
        status="SUCCESS",
        threat_level="Low",
        anomaly_score=0.0,
        details=f"User registered successfully. Role: {user.role}",
        user_id=user.id,
        username=user.username
    )

    return user

def authenticate_user(db: Session, username: str, password: str) -> dict:
    """Authenticate user credentials and issue JWT access token."""
    user = db.query(User).filter(User.username == username).first()
    activity = db.query(UserActivity).filter(UserActivity.user_id == user.id).first() if user else None

    if not user or not verify_password(password, user.password_hash):
        if activity:
            activity.failed_logins += 1
            activity.last_access_timestamp = datetime.datetime.utcnow()
            db.commit()

        log_security_event(
            db=db,
            activity_type="USER_LOGIN",
            status="FAILED",
            threat_level="Medium",
            anomaly_score=-0.08,
            details="Invalid username or password attempt",
            user_id=user.id if user else None,
            username=username
        )
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Reset failed login count on successful login
    if activity:
        activity.login_attempts += 1
        activity.failed_logins = 0
        activity.last_access_timestamp = datetime.datetime.utcnow()
        db.commit()

    user.last_login_at = datetime.datetime.utcnow()
    db.commit()

    access_token = create_access_token(data={"sub": user.username, "user_id": user.id, "role": user.role})

    log_security_event(
        db=db,
        activity_type="USER_LOGIN",
        status="SUCCESS",
        threat_level="Low",
        anomaly_score=0.0,
        details=f"User logged in successfully. Role: {user.role}",
        user_id=user.id,
        username=user.username
    )

    return {"access_token": access_token, "token_type": "bearer", "user": user}

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    """FastAPI Dependency for decoding JWT token and returning authenticated User."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate authentication credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exception
    username: str = payload.get("sub")
    if username is None:
        raise credentials_exception

    user = db.query(User).filter(User.username == username).first()
    if user is None:
        raise credentials_exception
    return user

def require_role(required_role: str):
    """FastAPI Dependency factory for Role-Based Access Control (RBAC)."""
    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role.upper() != required_role.upper():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation forbidden: Required role '{required_role.upper()}'"
            )
        return current_user
    return role_checker
