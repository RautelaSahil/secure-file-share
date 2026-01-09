from cryptography.fernet import Fernet
import base64
import os
import hashlib

def get_fernet():
    raw_key = os.getenv("FILE_ENCRYPTION_KEY")
    key = hashlib.sha256(raw_key.encode()).digest()
    return Fernet(base64.urlsafe_b64encode(key))

def encrypt_bytes(data: bytes) -> bytes:
    return get_fernet().encrypt(data)

def decrypt_bytes(data: bytes) -> bytes:
    return get_fernet().decrypt(data)
