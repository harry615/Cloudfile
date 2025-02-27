# crypto_utils.py
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet
import os
import base64

def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def serialize_private_key(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

def load_public_key(public_key_bytes):
    return serialization.load_pem_public_key(public_key_bytes)

def load_private_key(private_key_bytes):
    return serialization.load_pem_private_key(private_key_bytes, password=None)

def encrypt_file_key(file_key: bytes, public_key):
    return public_key.encrypt(
        file_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_file_key(encrypted_file_key: bytes, private_key):
    return private_key.decrypt(
        encrypted_file_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def encrypt_file(file_data: bytes, file_key: bytes):
    cipher = Fernet(file_key)
    return cipher.encrypt(file_data)

def decrypt_file(encrypted_data: bytes, file_key: bytes):
    cipher = Fernet(file_key)
    return cipher.decrypt(encrypted_data)