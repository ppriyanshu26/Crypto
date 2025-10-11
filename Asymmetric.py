from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# Generate a pair of keys 
def generate_keys():
    print("🔑 Generating key pair...")
    
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    
    print("✅ Keys generated!\n")
    
    return private_key, public_key

# Encrypt a message with the PUBLIC key
def encrypt(message, public_key):
    print(f"🔐 Encrypting: '{message}'")
    
    message_bytes = message.encode('utf-8')
    
    encrypted = public_key.encrypt(
        message_bytes,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    print("✅ Message encrypted!\n")
    return encrypted

# Decrypt the message with the PRIVATE key
def decrypt(encrypted_message, private_key):
    print("🔓 Decrypting message...")
    
    decrypted_bytes = private_key.decrypt(
        encrypted_message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    decrypted_message = decrypted_bytes.decode('utf-8')
    
    print(f"✅ Decrypted: '{decrypted_message}'\n")
    return decrypted_message

# Display the actual key values
def show_keys(private_key, public_key):
    from cryptography.hazmat.primitives import serialization
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    print("🔒 PRIVATE KEY:")
    print(private_pem.decode('utf-8'))
    print("\n🌐 PUBLIC KEY:")
    print(public_pem.decode('utf-8'))

print("=" * 50)
print("   ASYMMETRIC CRYPTOGRAPHY DEMO")
print("=" * 50)
print()

private_key, public_key = generate_keys()
show_keys(private_key, public_key)

secret_message = "Hello! This is a secret! 🔒"
print(f"📝 Original: '{secret_message}'\n")

encrypted = encrypt(secret_message, public_key)
print(f"🔐 Encrypted data (first 60 chars): {encrypted[:60]}...")
print(f"   Total size: {len(encrypted)} bytes\n")

decrypted = decrypt(encrypted, private_key)

if secret_message == decrypted:
    print("🎉 SUCCESS! Messages match!\n")
