import os
import uuid
import datetime
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, status, Query
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional

from backend.database import engine, Base, get_db
from backend.models import User, FileRecord, SecurityLog, UserActivity
from backend.schemas import (
    UserRegister, UserLogin, Token, UserOut,
    FileRecordOut, DecryptResponse, ThreatStatusResponse,
    SecurityLogOut, DashboardStatsResponse
)
from backend.auth import (
    hash_password, verify_password, create_access_token, get_current_user
)
from backend.encryption import encrypt_file_hybrid
from backend.decryption import decrypt_file_hybrid
from backend.ai_detection import get_threat_detector
from backend.security_logs import log_security_event, get_or_create_user_activity

# Create database tables
Base.metadata.create_all(bind=engine)

# Paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENCRYPTED_DIR = os.path.join(BASE_DIR, "uploads", "encrypted_files")
DECRYPTED_DIR = os.path.join(BASE_DIR, "uploads", "decrypted_files")
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

os.makedirs(ENCRYPTED_DIR, exist_ok=True)
os.makedirs(DECRYPTED_DIR, exist_ok=True)

app = FastAPI(
    title="AI-Enabled Hybrid File Encryption and Threat Detection System",
    description="CNS Academic Mini Project combining AES-256, RSA-2048, SHA-256 and Isolation Forest ML",
    version="1.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API Routes

@app.post("/api/auth/register", response_model=UserOut)
def register(user_data: UserRegister, db: Session = Depends(get_db)):
    # Check if username or email exists
    if db.query(User).filter(User.username == user_data.username).first():
        raise HTTPException(status_code=400, detail="Username already exists")
    if db.query(User).filter(User.email == user_data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")

    new_user = User(
        username=user_data.username,
        email=user_data.email,
        password_hash=hash_password(user_data.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Initialize user activity counter
    get_or_create_user_activity(db, new_user.id)

    log_security_event(
        db=db,
        user_id=new_user.id,
        username=new_user.username,
        activity_type="User Registration",
        status="Success",
        threat_level="Low",
        details=f"New user registered: {new_user.username}"
    )

    return new_user

@app.post("/api/auth/login", response_model=Token)
def login(login_data: UserLogin, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == login_data.username).first()

    if not user:
        log_security_event(
            db=db,
            user_id=None,
            username=login_data.username,
            activity_type="Failed Login",
            status="Failed",
            threat_level="Medium",
            details=f"Login attempt failed: Invalid username '{login_data.username}'"
        )
        raise HTTPException(status_code=401, detail="Invalid username or password")

    activity = get_or_create_user_activity(db, user.id)

    if not verify_password(login_data.password, user.password_hash):
        activity.failed_logins += 1
        db.commit()

        # Run AI threat check on failed login
        detector = get_threat_detector()
        ai_res = detector.predict_activity({
            "failed_logins": activity.failed_logins,
            "encryption_requests": activity.encryption_requests,
            "decryption_requests": activity.decryption_requests,
            "failed_decryptions": activity.failed_decryptions,
            "access_frequency": 2.0
        })

        log_security_event(
            db=db,
            user_id=user.id,
            username=user.username,
            activity_type="Failed Login",
            status="Failed",
            threat_level=ai_res["threat_level"],
            anomaly_score=ai_res["anomaly_score"],
            details=f"Password mismatch for user '{user.username}'. Total failed logins: {activity.failed_logins}"
        )

        raise HTTPException(status_code=401, detail="Invalid username or password")

    # Successful login
    activity.login_attempts += 1
    activity.last_access_timestamp = datetime.datetime.utcnow()
    db.commit()

    token = create_access_token({"sub": user.username})

    log_security_event(
        db=db,
        user_id=user.id,
        username=user.username,
        activity_type="Successful Login",
        status="Success",
        threat_level="Low",
        details=f"User '{user.username}' authenticated successfully."
    )

    return {"access_token": token, "token_type": "bearer", "username": user.username}

@app.get("/api/auth/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.post("/api/encrypt", response_model=FileRecordOut)
async def encrypt_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    # Perform Hybrid Encryption (AES-256 + RSA-2048 + SHA-256)
    crypto_res = encrypt_file_hybrid(file_bytes)

    # Save encrypted file payload to disk
    unique_filename = f"{uuid.uuid4().hex}_{file.filename}.enc"
    encrypted_file_path = os.path.join(ENCRYPTED_DIR, unique_filename)

    with open(encrypted_file_path, "wb") as f:
        f.write(crypto_res["encrypted_file_payload"])

    # Create database record
    file_record = FileRecord(
        user_id=current_user.id,
        original_filename=file.filename,
        encrypted_filename=unique_filename,
        encrypted_aes_key=crypto_res["encrypted_aes_key_b64"],
        sha256_hash=crypto_res["sha256_hash"],
        file_size=len(file_bytes)
    )
    db.add(file_record)

    # Update user activity
    activity = get_or_create_user_activity(db, current_user.id)
    activity.encryption_requests += 1
    activity.last_access_timestamp = datetime.datetime.utcnow()

    db.commit()
    db.refresh(file_record)

    # AI evaluation
    detector = get_threat_detector()
    ai_res = detector.predict_activity({
        "failed_logins": activity.failed_logins,
        "encryption_requests": activity.encryption_requests,
        "decryption_requests": activity.decryption_requests,
        "failed_decryptions": activity.failed_decryptions,
        "access_frequency": 1.5
    })

    log_security_event(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        activity_type="File Encryption",
        status="Success",
        threat_level=ai_res["threat_level"],
        anomaly_score=ai_res["anomaly_score"],
        details=f"Encrypted file '{file.filename}' (AES-256 & RSA-2048 protected). SHA-256: {crypto_res['sha256_hash'][:16]}..."
    )

    return file_record

@app.get("/api/files", response_model=List[FileRecordOut])
def get_user_files(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    files = db.query(FileRecord).filter(FileRecord.user_id == current_user.id).order_by(FileRecord.encryption_timestamp.desc()).all()
    return files

@app.post("/api/decrypt/{file_id}", response_model=DecryptResponse)
def decrypt_file(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    file_record = db.query(FileRecord).filter(FileRecord.id == file_id).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="Encrypted file record not found")

    if file_record.user_id != current_user.id:
        # Unauthorized attempt by another user
        log_security_event(
            db=db,
            user_id=current_user.id,
            username=current_user.username,
            activity_type="Unauthorized Decryption Access",
            status="Blocked",
            threat_level="High",
            anomaly_score=-0.35,
            details=f"User '{current_user.username}' attempted unauthorized decryption of file ID {file_id}"
        )
        raise HTTPException(status_code=403, detail="Unauthorized access to requested file")

    activity = get_or_create_user_activity(db, current_user.id)
    activity.decryption_requests += 1

    # AI Threat Detection Check before allowing decryption
    detector = get_threat_detector()
    ai_eval = detector.predict_activity({
        "failed_logins": activity.failed_logins,
        "encryption_requests": activity.encryption_requests,
        "decryption_requests": activity.decryption_requests,
        "failed_decryptions": activity.failed_decryptions,
        "access_frequency": 3.0 if activity.failed_decryptions > 2 else 1.0
    })

    if ai_eval["classification"] == "POTENTIAL THREAT":
        log_security_event(
            db=db,
            user_id=current_user.id,
            username=current_user.username,
            activity_type="Decryption Blocked by AI",
            status="Blocked",
            threat_level="High",
            anomaly_score=ai_eval["anomaly_score"],
            details=f"AI Isolation Forest blocked decryption for file '{file_record.original_filename}'. {ai_eval['explanation']}"
        )
        return DecryptResponse(
            status="BLOCKED",
            integrity_verified=False,
            message=f"🚨 ACCESS BLOCKED BY AI THREAT DETECTION. {ai_eval['explanation']}",
            original_filename=file_record.original_filename,
            original_hash=file_record.sha256_hash,
            computed_hash="N/A",
            download_url=None,
            anomaly_score=ai_eval["anomaly_score"],
            threat_level=ai_eval["threat_level"]
        )

    # Load encrypted payload
    encrypted_file_path = os.path.join(ENCRYPTED_DIR, file_record.encrypted_filename)
    if not os.path.exists(encrypted_file_path):
        raise HTTPException(status_code=404, detail="Encrypted file payload missing on server disk")

    with open(encrypted_file_path, "rb") as f:
        encrypted_payload = f.read()

    # Perform Decryption
    dec_res = decrypt_file_hybrid(
        encrypted_payload=encrypted_payload,
        encrypted_aes_key_b64=file_record.encrypted_aes_key,
        expected_sha256=file_record.sha256_hash
    )

    if not dec_res["success"] or not dec_res["integrity_verified"]:
        activity.failed_decryptions += 1
        db.commit()

        log_security_event(
            db=db,
            user_id=current_user.id,
            username=current_user.username,
            activity_type="Integrity Verification Failure",
            status="Failed",
            threat_level="High",
            anomaly_score=ai_eval["anomaly_score"],
            details=f"File integrity verification failed for '{file_record.original_filename}'. Hash mismatch!"
        )

        return DecryptResponse(
            status="INTEGRITY_FAILED",
            integrity_verified=False,
            message="🚨 FILE INTEGRITY FAILED! Checksum mismatch detected.",
            original_filename=file_record.original_filename,
            original_hash=file_record.sha256_hash,
            computed_hash=dec_res["computed_sha256"],
            download_url=None,
            anomaly_score=ai_eval["anomaly_score"],
            threat_level="High"
        )

    # Save decrypted file for user download
    decrypted_filename = f"decrypted_{file_record.original_filename}"
    decrypted_file_path = os.path.join(DECRYPTED_DIR, decrypted_filename)
    with open(decrypted_file_path, "wb") as f:
        f.write(dec_res["decrypted_bytes"])

    db.commit()

    log_security_event(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        activity_type="File Decryption",
        status="Success",
        threat_level="Low",
        anomaly_score=ai_eval["anomaly_score"],
        details=f"Decrypted '{file_record.original_filename}' successfully. SHA-256 integrity verified."
    )

    return DecryptResponse(
        status="SUCCESS",
        integrity_verified=True,
        message="✅ FILE INTEGRITY VERIFIED",
        original_filename=file_record.original_filename,
        original_hash=file_record.sha256_hash,
        computed_hash=dec_res["computed_sha256"],
        download_url=f"/api/download/{decrypted_filename}",
        anomaly_score=ai_eval["anomaly_score"],
        threat_level=ai_eval["threat_level"]
    )

@app.get("/api/download/{filename}")
def download_decrypted_file(
    filename: str,
    current_user: User = Depends(get_current_user)
):
    file_path = os.path.join(DECRYPTED_DIR, filename)
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found or expired")
    return FileResponse(file_path, filename=filename.replace("decrypted_", ""))

@app.get("/api/threat-detection/status", response_model=ThreatStatusResponse)
def get_threat_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    activity = get_or_create_user_activity(db, current_user.id)
    detector = get_threat_detector()

    ai_eval = detector.predict_activity({
        "failed_logins": activity.failed_logins,
        "encryption_requests": activity.encryption_requests,
        "decryption_requests": activity.decryption_requests,
        "failed_decryptions": activity.failed_decryptions,
        "access_frequency": 4.0 if activity.failed_decryptions > 1 else 1.0
    })

    return ThreatStatusResponse(
        status=ai_eval["classification"],
        anomaly_score=ai_eval["anomaly_score"],
        threat_level=ai_eval["threat_level"],
        failed_logins=activity.failed_logins,
        encryption_requests=activity.encryption_requests,
        decryption_requests=activity.decryption_requests,
        failed_decryptions=activity.failed_decryptions,
        explanation=ai_eval["explanation"]
    )

@app.post("/api/ai/simulate-attack")
def simulate_attack(
    attack_type: str = Query("failed_decryptions", description="Type of attack simulation"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Endpoint for demonstration/viva to trigger simulated threat behavior."""
    activity = get_or_create_user_activity(db, current_user.id)

    if attack_type == "failed_decryptions":
        activity.failed_decryptions += 4
        event_name = "Simulated Brute-Force Decryption Attack"
    elif attack_type == "failed_logins":
        activity.failed_logins += 5
        event_name = "Simulated Credential Stuffing Attack"
    else:
        activity.failed_decryptions += 2
        activity.failed_logins += 2
        event_name = "Simulated Anomaly Attack"

    db.commit()

    detector = get_threat_detector()
    ai_eval = detector.predict_activity({
        "failed_logins": activity.failed_logins,
        "encryption_requests": activity.encryption_requests,
        "decryption_requests": activity.decryption_requests,
        "failed_decryptions": activity.failed_decryptions,
        "access_frequency": 20.0
    })

    log_security_event(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        activity_type=event_name,
        status="Alert Triggered",
        threat_level="High",
        anomaly_score=ai_eval["anomaly_score"],
        details=f"DEMO VIVA ATTACK SIMULATED: {event_name}. Threat state changed to {ai_eval['classification']}"
    )

    return {
        "message": f"Attack simulation executed: {event_name}",
        "new_status": ai_eval["classification"],
        "anomaly_score": ai_eval["anomaly_score"],
        "threat_level": ai_eval["threat_level"]
    }

@app.post("/api/ai/reset-simulation")
def reset_simulation(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    activity = get_or_create_user_activity(db, current_user.id)
    activity.failed_decryptions = 0
    activity.failed_logins = 0
    db.commit()

    log_security_event(
        db=db,
        user_id=current_user.id,
        username=current_user.username,
        activity_type="Threat State Reset",
        status="Success",
        threat_level="Low",
        anomaly_score=0.1,
        details="User reset activity anomaly counters back to normal state."
    )

    return {"message": "User anomaly metrics reset to normal baseline."}

@app.get("/api/dashboard/stats", response_model=DashboardStatsResponse)
def get_dashboard_stats(db: Session = Depends(get_db)):
    total_users = db.query(User).count()
    total_files_encrypted = db.query(FileRecord).count()

    total_files_decrypted = db.query(SecurityLog).filter(
        SecurityLog.activity_type == "File Decryption",
        SecurityLog.status == "Success"
    ).count()

    normal_activities = db.query(SecurityLog).filter(SecurityLog.threat_level == "Low").count()
    suspicious_activities = db.query(SecurityLog).filter(SecurityLog.threat_level == "Medium").count()
    threat_alerts = db.query(SecurityLog).filter(SecurityLog.threat_level == "High").count()

    threat_level_distribution = {
        "Low": normal_activities,
        "Medium": suspicious_activities,
        "High": threat_alerts
    }

    # Generate sample timeline metrics for charts
    logs = db.query(SecurityLog).order_by(SecurityLog.timestamp.desc()).limit(20).all()
    activity_over_time = [
        {
            "timestamp": log.timestamp.strftime("%H:%M:%S"),
            "activity": log.activity_type,
            "threat_level": log.threat_level,
            "score": log.anomaly_score
        }
        for log in reversed(logs)
    ]

    return DashboardStatsResponse(
        total_users=total_users,
        total_files_encrypted=total_files_encrypted,
        total_files_decrypted=total_files_decrypted,
        normal_activities=normal_activities,
        suspicious_activities=suspicious_activities,
        threat_alerts=threat_alerts,
        threat_level_distribution=threat_level_distribution,
        activity_over_time=activity_over_time
    )

@app.get("/api/logs", response_model=List[SecurityLogOut])
def get_security_logs(
    search: Optional[str] = Query(None),
    threat_level: Optional[str] = Query(None),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db)
):
    query = db.query(SecurityLog)

    if threat_level and threat_level.lower() != "all":
        query = query.filter(SecurityLog.threat_level == threat_level)

    if search:
        search_pattern = f"%{search}%"
        query = query.filter(
            (SecurityLog.username.like(search_pattern)) |
            (SecurityLog.activity_type.like(search_pattern)) |
            (SecurityLog.status.like(search_pattern)) |
            (SecurityLog.details.like(search_pattern))
        )

    logs = query.order_by(SecurityLog.timestamp.desc()).limit(limit).all()
    return logs

# Serve Static Frontend Files
app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

@app.get("/")
def read_root():
    return FileResponse(os.path.join(FRONTEND_DIR, "index.html"))
