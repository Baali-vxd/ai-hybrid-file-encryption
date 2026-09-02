import datetime
from typing import Dict, Any
from backend.db.models.activity import UserActivity

def extract_feature_vector(activity: UserActivity) -> Dict[str, Any]:
    """
    Extract feature vector dictionary from UserActivity ORM model:
    - failed_logins (int)
    - encryption_requests (int)
    - decryption_requests (int)
    - failed_decryptions (int)
    - access_frequency (float, requests per min)
    """
    if not activity:
        return {
            "failed_logins": 0,
            "encryption_requests": 0,
            "decryption_requests": 0,
            "failed_decryptions": 0,
            "access_frequency": 1.0
        }

    # Calculate access frequency rate
    time_diff = (datetime.datetime.utcnow() - (activity.last_access_timestamp or datetime.datetime.utcnow())).total_seconds()
    minutes = max(time_diff / 60.0, 0.1)
    total_reqs = activity.encryption_requests + activity.decryption_requests + activity.login_attempts
    access_freq = round(total_reqs / minutes, 2)

    return {
        "failed_logins": activity.failed_logins,
        "encryption_requests": activity.encryption_requests,
        "decryption_requests": activity.decryption_requests,
        "failed_decryptions": activity.failed_decryptions,
        "access_frequency": access_freq
    }
