import os
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from backend.core.config import settings

def ensure_rsa_keys():
    """Ensure RSA-2048 key pair exists on disk, generating if missing."""
    priv_path = settings.RSA_PRIVATE_KEY_PATH
    pub_path = settings.RSA_PUBLIC_KEY_PATH
    
    os.makedirs(os.path.dirname(os.path.abspath(priv_path)), exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(pub_path)), exist_ok=True)

    if not os.path.exists(priv_path) or not os.path.exists(pub_path):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        public_key = private_key.public_key()

        pem_private = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(priv_path, "wb") as f:
            f.write(pem_private)

        pem_public = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        with open(pub_path, "wb") as f:
            f.write(pem_public)

def load_public_key():
    ensure_rsa_keys()
    with open(settings.RSA_PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_private_key():
    ensure_rsa_keys()
    with open(settings.RSA_PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def encrypt_aes_key_rsa(aes_key: bytes) -> str:
    """Encrypt 256-bit AES secret key using RSA-2048 Public Key (OAEP). Returns base64 encoded string."""
    public_key = load_public_key()
    encrypted_bytes = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted_bytes).decode('utf-8')

def decrypt_aes_key_rsa(encrypted_aes_key_b64: str) -> bytes:
    """Decrypt base64 RSA-encrypted AES secret key using RSA-2048 Private Key (OAEP)."""
    encrypted_bytes = base64.b64decode(encrypted_aes_key_b64)
    private_key = load_private_key()
    return private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
