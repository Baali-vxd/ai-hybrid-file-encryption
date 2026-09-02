from backend.crypto.hashing import calculate_sha256
from backend.crypto.aes import encrypt_aes_gcm, decrypt_aes_gcm
from backend.crypto.rsa import encrypt_aes_key_rsa, decrypt_aes_key_rsa

def encrypt_hybrid(file_bytes: bytes) -> dict:
    """
    Execute complete hybrid encryption pipeline:
    1. Calculate SHA-256 integrity digest.
    2. Encrypt raw payload with AES-256-GCM.
    3. Protect AES key with RSA-2048 OAEP public key wrapping.
    """
    sha256_hash = calculate_sha256(file_bytes)
    encrypted_payload, aes_key, iv, tag = encrypt_aes_gcm(file_bytes)
    encrypted_aes_key_b64 = encrypt_aes_key_rsa(aes_key)

    return {
        "sha256_hash": sha256_hash,
        "encrypted_file_payload": encrypted_payload,
        "encrypted_aes_key_b64": encrypted_aes_key_b64,
        "aes_key_length_bits": 256,
        "rsa_key_length_bits": 2048
    }

def decrypt_hybrid(encrypted_payload: bytes, encrypted_aes_key_b64: str, expected_sha256: str) -> dict:
    """
    Execute complete hybrid decryption & integrity verification pipeline:
    1. Unwrap AES key using RSA-2048 OAEP private key.
    2. Decrypt file payload with AES-256-GCM.
    3. Verify decrypted file SHA-256 against expected_sha256.
    """
    try:
        aes_key = decrypt_aes_key_rsa(encrypted_aes_key_b64)
        decrypted_bytes = decrypt_aes_gcm(encrypted_payload, aes_key)
        computed_sha256 = calculate_sha256(decrypted_bytes)
        integrity_verified = (computed_sha256.lower() == expected_sha256.lower())

        return {
            "success": True,
            "integrity_verified": integrity_verified,
            "decrypted_bytes": decrypted_bytes if integrity_verified else None,
            "computed_sha256": computed_sha256,
            "expected_sha256": expected_sha256,
            "message": "FILE INTEGRITY VERIFIED" if integrity_verified else "FILE INTEGRITY FAILED"
        }
    except Exception as e:
        return {
            "success": False,
            "integrity_verified": False,
            "decrypted_bytes": None,
            "computed_sha256": "",
            "expected_sha256": expected_sha256,
            "message": f"Decryption failure or integrity compromise: {str(e)}"
        }
