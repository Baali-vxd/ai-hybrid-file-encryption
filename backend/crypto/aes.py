import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

def encrypt_aes_gcm(file_bytes: bytes, aes_key: bytes = None) -> tuple[bytes, bytes, bytes, bytes]:
    """
    Encrypt binary payload with AES-256-GCM.
    Returns: (encrypted_payload [IV + TAG + CIPHERTEXT], aes_key [32 bytes], iv [12 bytes], tag [16 bytes])
    """
    if not aes_key:
        aes_key = os.urandom(32)  # 256-bit AES key
    iv = os.urandom(12)           # 96-bit IV for GCM mode

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(file_bytes) + encryptor.finalize()
    tag = encryptor.tag

    # Full payload: 12-byte IV + 16-byte TAG + Ciphertext
    encrypted_payload = iv + tag + ciphertext
    return encrypted_payload, aes_key, iv, tag

def decrypt_aes_gcm(encrypted_payload: bytes, aes_key: bytes) -> bytes:
    """
    Decrypt payload with AES-256-GCM using key and payload components.
    Expects encrypted_payload layout: IV (12 bytes) + TAG (16 bytes) + CIPHERTEXT
    """
    iv = encrypted_payload[:12]
    tag = encrypted_payload[12:28]
    ciphertext = encrypted_payload[28:]

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag))
    decryptor = cipher.decryptor()
    decrypted_bytes = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_bytes
