import os
import uuid
import datetime
from fastapi import HTTPException
from sqlalchemy.orm import Session
from backend.core.config import settings
from backend.db.models.user import User
from backend.db.models.file import FileRecord
from backend.db.models.activity import UserActivity
from backend.crypto.hybrid import encrypt_hybrid, decrypt_hybrid
from backend.ml.features import extract_feature_vector
from backend.ml.detector import get_threat_detector
from backend.core.logging import log_security_event

def process_file_encryption(db: Session, user: User, file_bytes: bytes, original_filename: str) -> FileRecord:
    """Execute hybrid encryption on uploaded file bytes and persist payload."""
    os.makedirs(settings.STORAGE_ENCRYPTED_DIR, exist_ok=True)
    
    # 1. Run hybrid encryption pipeline
    crypto_result = encrypt_hybrid(file_bytes)

    # 2. Save encrypted payload to disk
    encrypted_filename = f"{uuid.uuid4().hex}.enc"
    encrypted_file_path = os.path.join(settings.STORAGE_ENCRYPTED_DIR, encrypted_filename)
    with open(encrypted_file_path, "wb") as f:
        f.write(crypto_result["encrypted_file_payload"])

    # 3. Create database record
    file_record = FileRecord(
        user_id=user.id,
        original_filename=original_filename,
        encrypted_filename=encrypted_filename,
        encrypted_aes_key=crypto_result["encrypted_aes_key_b64"],
        sha256_hash=crypto_result["sha256_hash"],
        file_size=len(file_bytes),
        encryption_algorithm="AES-256-GCM",
        key_algorithm="RSA-2048-OAEP"
    )
    db.add(file_record)

    # 4. Update user activity tracking
    activity = db.query(UserActivity).filter(UserActivity.user_id == user.id).first()
    if activity:
        activity.encryption_requests += 1
        activity.last_access_timestamp = datetime.datetime.utcnow()

    db.commit()
    db.refresh(file_record)

    log_security_event(
        db=db,
        activity_type="FILE_ENCRYPTION",
        status="SUCCESS",
        threat_level="Low",
        anomaly_score=0.0,
        details=f"Encrypted file: {original_filename} ({len(file_bytes)} bytes) -> {encrypted_filename}",
        user_id=user.id,
        username=user.username
    )

    return file_record

def process_file_decryption(db: Session, user: User, file_id: int) -> dict:
    """Evaluate threat score and execute hybrid decryption with SHA-256 integrity verification."""
    file_record = db.query(FileRecord).filter(FileRecord.id == file_id).first()
    if not file_record:
        raise HTTPException(status_code=404, detail="File record not found")

    # Check ownership (unless user is ADMIN)
    if file_record.user_id != user.id and user.role.upper() != "ADMIN":
        raise HTTPException(status_code=403, detail="Unauthorized access to file record")

    # 1. Fetch user activity & evaluate AI threat detector
    activity = db.query(UserActivity).filter(UserActivity.user_id == user.id).first()
    if not activity:
        activity = UserActivity(user_id=user.id)
        db.add(activity)
        db.commit()

    features = extract_feature_vector(activity)
    detector = get_threat_detector()
    assessment = detector.predict_activity(features)

    # 2. Block decryption if POTENTIAL THREAT is detected
    if assessment["classification"] == "POTENTIAL THREAT":
        activity.failed_decryptions += 1
        activity.last_access_timestamp = datetime.datetime.utcnow()
        db.commit()

        log_security_event(
            db=db,
            activity_type="FILE_DECRYPTION_BLOCKED",
            status="BLOCKED_BY_AI",
            threat_level="High",
            anomaly_score=assessment["anomaly_score"],
            details=f"Decryption blocked for file #{file_id} ({file_record.original_filename}). Reason: {assessment['explanation']}",
            user_id=user.id,
            username=user.username
        )

        return {
            "status": "BLOCKED",
            "message": f"🚨 SECURITY ALERT: Decryption request blocked by AI Threat Engine! Threat Level: {assessment['threat_level']}",
            "anomaly_score": assessment["anomaly_score"],
            "threat_level": assessment["threat_level"],
            "original_hash": file_record.sha256_hash,
            "computed_hash": "N/A (Blocked)",
            "integrity_verified": False,
            "download_url": None
        }

    # 3. Read encrypted file payload from disk
    encrypted_file_path = os.path.join(settings.STORAGE_ENCRYPTED_DIR, file_record.encrypted_filename)
    if not os.path.exists(encrypted_file_path):
        raise HTTPException(status_code=404, detail="Encrypted payload file missing from storage")

    with open(encrypted_file_path, "rb") as f:
        encrypted_payload = f.read()

    # 4. Decrypt hybrid payload
    result = decrypt_hybrid(
        encrypted_payload=encrypted_payload,
        encrypted_aes_key_b64=file_record.encrypted_aes_key,
        expected_sha256=file_record.sha256_hash
    )

    activity.decryption_requests += 1
    activity.last_access_timestamp = datetime.datetime.utcnow()

    if result["success"] and result["integrity_verified"]:
        # Save temporary decrypted file for download
        os.makedirs(settings.STORAGE_DECRYPTED_DIR, exist_ok=True)
        decrypted_filename = f"decrypted_{uuid.uuid4().hex[:8]}_{file_record.original_filename}"
        decrypted_file_path = os.path.join(settings.STORAGE_DECRYPTED_DIR, decrypted_filename)
        with open(decrypted_file_path, "wb") as f:
            f.write(result["decrypted_bytes"])

        db.commit()

        log_security_event(
            db=db,
            activity_type="FILE_DECRYPTION",
            status="SUCCESS",
            threat_level="Low",
            anomaly_score=assessment["anomaly_score"],
            details=f"Decrypted file #{file_id} ({file_record.original_filename}). SHA-256 Integrity Verified.",
            user_id=user.id,
            username=user.username
        )

        return {
            "status": "SUCCESS",
            "message": "✅ FILE INTEGRITY VERIFIED - Decryption Completed",
            "anomaly_score": assessment["anomaly_score"],
            "threat_level": assessment["threat_level"],
            "original_hash": file_record.sha256_hash,
            "computed_hash": result["computed_sha256"],
            "integrity_verified": True,
            "download_url": f"/api/v1/files/download/{decrypted_filename}"
        }
    else:
        activity.failed_decryptions += 1
        db.commit()

        log_security_event(
            db=db,
            activity_type="FILE_DECRYPTION",
            status="INTEGRITY_FAILED",
            threat_level="High",
            anomaly_score=assessment["anomaly_score"],
            details=f"Decryption integrity failure for file #{file_id}: {result['message']}",
            user_id=user.id,
            username=user.username
        )

        return {
            "status": "FAILED",
            "message": f"🚨 FILE INTEGRITY FAILED: {result['message']}",
            "anomaly_score": assessment["anomaly_score"],
            "threat_level": "High",
            "original_hash": file_record.sha256_hash,
            "computed_hash": result.get("computed_sha256", "Invalid"),
            "integrity_verified": False,
            "download_url": None
        }
