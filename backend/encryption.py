import os
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

KEYS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "uploads", "keys")
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "rsa_private.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "rsa_public.pem")

def ensure_rsa_keys():
    """Ensure RSA-2048 key pair exists, or generate a new key pair."""
    os.makedirs(KEYS_DIR, exist_ok=True)
    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        # Save private key
        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(pem_private)

        # Save public key
        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(pem_public)

def load_public_key():
    ensure_rsa_keys()
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_private_key():
    ensure_rsa_keys()
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def calculate_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of binary data."""
    return hashlib.sha256(data).hexdigest()

def encrypt_file_hybrid(file_bytes: bytes) -> dict:
    """
    Hybrid Encryption Workflow:
    1. Compute SHA-256 hash of original file content.
    2. Generate random 256-bit (32 byte) AES key.
    3. Encrypt file_bytes using AES-256-GCM.
    4. Encrypt AES key using RSA-2048 OAEP public key.
    5. Base64 encode encrypted AES key for storage.
    """
    # 1. SHA-256 hash of original file
    sha256_hash = calculate_sha256(file_bytes)

    # 2. Random 256-bit AES key & 96-bit (12-byte) IV for GCM
    aes_key = os.urandom(32)  # 256-bit AES key
    iv = os.urandom(12)       # 96-bit IV

    # 3. Encrypt file using AES-256-GCM
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(file_bytes) + encryptor.finalize()
    tag = encryptor.tag

    # Combine IV (12 bytes) + TAG (16 bytes) + CIPHERTEXT
    encrypted_file_payload = iv + tag + ciphertext

    # 4. Encrypt AES key with RSA-2048 Public Key
    public_key = load_public_key()
    encrypted_aes_key_bytes = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Base64 encode encrypted AES key
    encrypted_aes_key_b64 = base64.b64encode(encrypted_aes_key_bytes).decode('utf-8')

    return {
        "sha256_hash": sha256_hash,
        "encrypted_file_payload": encrypted_file_payload,
        "encrypted_aes_key_b64": encrypted_aes_key_b64,
        "aes_key_length_bits": 256,
        "rsa_key_length_bits": 2048
    }
