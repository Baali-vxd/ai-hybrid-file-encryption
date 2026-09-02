import pytest
from backend.crypto.aes import encrypt_aes_gcm, decrypt_aes_gcm
from backend.crypto.rsa import encrypt_aes_key_rsa, decrypt_aes_key_rsa
from backend.crypto.hashing import calculate_sha256
from backend.crypto.hybrid import encrypt_hybrid, decrypt_hybrid

def test_sha256_hash_calculation():
    data = b"Hello, Computer Networks and Security!"
    digest1 = calculate_sha256(data)
    digest2 = calculate_sha256(data)
    assert digest1 == digest2
    assert len(digest1) == 64

def test_aes_gcm_encryption_decryption():
    plaintext = b"Top secret file contents for hybrid encryption testing."
    encrypted_payload, aes_key, iv, tag = encrypt_aes_gcm(plaintext)
    
    assert len(aes_key) == 32
    assert len(iv) == 12
    assert len(tag) == 16
    assert encrypted_payload != plaintext

    decrypted = decrypt_aes_gcm(encrypted_payload, aes_key)
    assert decrypted == plaintext

def test_rsa_key_wrapping():
    sample_aes_key = b"12345678901234567890123456789012"  # 32 bytes
    wrapped_b64 = encrypt_aes_key_rsa(sample_aes_key)
    assert isinstance(wrapped_b64, str)

    unwrapped_key = decrypt_aes_key_rsa(wrapped_b64)
    assert unwrapped_key == sample_aes_key

def test_full_hybrid_pipeline_success():
    payload = b"Full pipeline binary payload test string."
    res = encrypt_hybrid(payload)

    assert "sha256_hash" in res
    assert "encrypted_file_payload" in res
    assert "encrypted_aes_key_b64" in res

    dec_res = decrypt_hybrid(
        encrypted_payload=res["encrypted_file_payload"],
        encrypted_aes_key_b64=res["encrypted_aes_key_b64"],
        expected_sha256=res["sha256_hash"]
    )

    assert dec_res["success"] is True
    assert dec_res["integrity_verified"] is True
    assert dec_res["decrypted_bytes"] == payload

def test_hybrid_decryption_tamper_rejection():
    payload = b"Original uncorrupted content."
    res = encrypt_hybrid(payload)

    # Tamper with expected hash
    dec_res = decrypt_hybrid(
        encrypted_payload=res["encrypted_file_payload"],
        encrypted_aes_key_b64=res["encrypted_aes_key_b64"],
        expected_sha256="0000000000000000000000000000000000000000000000000000000000000000"
    )

    assert dec_res["success"] is True
    assert dec_res["integrity_verified"] is False
    assert dec_res["decrypted_bytes"] is None
