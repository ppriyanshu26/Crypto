import hashlib
import base64
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# ------------------- KEY VALIDATION -------------------
def key_length(key, min_length=8):
    if len(key) < min_length:
        raise ValueError(f"Key must be more than {min_length} characters long. Current length: {len(key)}")
    return True

# ------------------- AES-256 ENCRYPTION -------------------
def encrypt_aes256(plaintext, key_str):
    key = hashlib.sha256(key_str.encode()).digest()
    iv = os.urandom(16)
    
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext.encode()) + padder.finalize()
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return base64.urlsafe_b64encode(iv + ciphertext).decode()

# ------------------- AES-256 DECRYPTION -------------------
def decrypt_aes256(ciphertext_b64, key_str):
    key = hashlib.sha256(key_str.encode()).digest()

    raw = base64.urlsafe_b64decode(ciphertext_b64)
    iv, ciphertext = raw[:16], raw[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    
    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    
    return plaintext.decode()

# ------------------- MAIN -------------------
print("=== AES-256 Encryption / Decryption Tool ===\n")
key = input("Enter encryption key: ").strip()

try:
    key_length(key)
    print("✓ Key validation passed\n")
except ValueError as e:
    print(f"❌ Error: {e}")
    exit(1)

text = input("Enter text to encrypt: ").strip()

encrypted = encrypt_aes256(text, key)
print("\n🔒 Encrypted (Base64):")
print(encrypted)

decrypted = decrypt_aes256(encrypted, key)
print("\n🔓 Decrypted back:")
print(decrypted)
