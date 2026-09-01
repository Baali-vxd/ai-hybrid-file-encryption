import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from backend.encryption import load_private_key, calculate_sha256

def decrypt_file_hybrid(encrypted_payload: bytes, encrypted_aes_key_b64: str, expected_sha256: str) -> dict:
    """
    Decryption Workflow:
    1. Base64 decode encrypted AES key.
    2. Decrypt AES key using RSA-2048 Private Key (OAEP).
    3. Extract IV (12 bytes), TAG (16 bytes), and CIPHERTEXT from payload.
    4. Decrypt file content using AES-256-GCM.
    5. Calculate SHA-256 hash of decrypted content.
    6. Verify checksum equality with expected_sha256.
    """
    try:
        # 1. Base64 decode encrypted AES key
        encrypted_aes_key_bytes = base64.b64decode(encrypted_aes_key_b64)

        # 2. Decrypt AES key using RSA-2048 Private Key
        private_key = load_private_key()
        aes_key = private_key.decrypt(
            encrypted_aes_key_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # 3. Extract IV, TAG, and CIPHERTEXT
        iv = encrypted_payload[:12]
        tag = encrypted_payload[12:28]
        ciphertext = encrypted_payload[28:]

        # 4. Decrypt using AES-256-GCM
        cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()

        # 5. Compute SHA-256 hash
        computed_sha256 = calculate_sha256(decrypted_bytes)

        # 6. Verify checksum
        integrity_verified = (computed_sha256.lower() == expected_sha256.lower())

        return {
            "success": True,
            "integrity_verified": integrity_verified,
            "decrypted_bytes": decrypted_bytes,
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
