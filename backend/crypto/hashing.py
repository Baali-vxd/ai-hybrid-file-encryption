import hashlib

def calculate_sha256(data: bytes) -> str:
    """Compute 256-bit SHA-256 cryptographic hash (hexadecimal digest) of data."""
    return hashlib.sha256(data).hexdigest()
