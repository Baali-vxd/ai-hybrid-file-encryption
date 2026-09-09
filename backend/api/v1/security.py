from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from backend.db.database import get_db
from backend.db.models.user import User
from backend.schemas.security_schemas import ThreatStatusResponse, SecurityLogResponse
from backend.services.auth_service import get_current_user
from backend.services.threat_service import get_user_threat_status, simulate_attack_event, reset_user_simulation
from backend.services.audit_service import fetch_security_logs

router = APIRouter(prefix="/security", tags=["Threat Detection & Audit Logs"])

@router.get("/threat-status", response_model=ThreatStatusResponse)
def get_threat_status(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return get_user_threat_status(db, current_user)

@router.get("/logs", response_model=List[SecurityLogResponse])
def get_security_logs(threat_level: Optional[str] = Query("All"), search: Optional[str] = Query(None), limit: int = Query(50), db: Session = Depends(get_db)):
    return fetch_security_logs(db, threat_level=threat_level, search=search, limit=limit)

@router.post("/demo/simulate")
def trigger_attack_simulation(attack_type: str = Query("brute_force"), current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return simulate_attack_event(db, current_user, attack_type)

@router.post("/demo/reset")
def reset_simulation(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return reset_user_simulation(db, current_user)
