"""
KEY EXCHANGE: How 2 People Get a Shared Symmetric Key
======================================================
Problem: Asymmetric encryption is SLOW
Solution: Use asymmetric keys to exchange a symmetric key, then use that for fast communication!

This demonstrates Diffie-Hellman Key Exchange
"""

from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


def generate_parameters():
    """Generate shared parameters (can be public!)"""
    print("🔧 Generating DH parameters (this can be public)...")
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    print("✅ Parameters generated!\n")
    return parameters


def generate_dh_keypair(parameters):
    """Each person generates their own key pair"""
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key


def derive_shared_key(my_private_key, their_public_key):
    """Create the shared secret using my private key + their public key"""
    shared_secret = my_private_key.exchange(their_public_key)
    
    # Convert the shared secret to a proper symmetric key (32 bytes for AES-256)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(shared_secret)
    
    return derived_key


def encrypt_symmetric(message, key):
    """Encrypt using the shared symmetric key (FAST!)"""
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)
    
    # Create cipher
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    
    # Encrypt
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    
    return iv + ciphertext  # Send IV with ciphertext


def decrypt_symmetric(encrypted_data, key):
    """Decrypt using the shared symmetric key (FAST!)"""
    # Extract IV and ciphertext
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    # Create cipher
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    
    # Decrypt
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext.decode()


def main():
    print("=" * 70)
    print("   HOW TWO PEOPLE AGREE ON A SHARED KEY (Diffie-Hellman)")
    print("=" * 70)
    print()
    
    # Step 1: Generate shared parameters (public, everyone can see)
    print("📋 STEP 1: Create public parameters")
    parameters = generate_parameters()
    
    # Step 2: Alice generates her key pair
    print("👩 STEP 2: Alice generates her key pair")
    alice_private, alice_public = generate_dh_keypair(parameters)
    print("   Alice has: Private key (secret) + Public key (shares)\n")
    
    # Step 3: Bob generates his key pair
    print("👨 STEP 3: Bob generates his key pair")
    bob_private, bob_public = generate_dh_keypair(parameters)
    print("   Bob has: Private key (secret) + Public key (shares)\n")
    
    print("-" * 70)
    print("🌐 Alice and Bob EXCHANGE public keys (over insecure channel - OK!)")
    print("-" * 70)
    print()
    
    # Step 4: Both derive the SAME shared key!
    print("🔑 STEP 4: Both compute the shared secret")
    print("   Alice computes: Her private key + Bob's public key")
    alice_shared_key = derive_shared_key(alice_private, bob_public)
    
    print("   Bob computes: His private key + Alice's public key")
    bob_shared_key = derive_shared_key(bob_private, alice_public)
    
    # Verify they got the same key!
    if alice_shared_key == bob_shared_key:
        print("   ✅ MAGIC! Both have the SAME symmetric key!\n")
        print(f"   Shared key (first 16 bytes): {alice_shared_key[:16].hex()}\n")
    else:
        print("   ❌ ERROR: Keys don't match!\n")
        return
    
    # Step 5: Now they can use fast symmetric encryption!
    print("=" * 70)
    print("   NOW THEY CAN CHAT USING FAST SYMMETRIC ENCRYPTION!")
    print("=" * 70)
    print()
    
    # Alice sends a message
    print("👩 Alice: Encrypting message with shared key...")
    message1 = "Hi Bob! This is encrypted with our shared key! 🚀"
    encrypted1 = encrypt_symmetric(message1, alice_shared_key)
    print(f"   Sent: {encrypted1[:40].hex()}... ({len(encrypted1)} bytes)\n")
    
    # Bob decrypts
    print("👨 Bob: Decrypting message with shared key...")
    decrypted1 = decrypt_symmetric(encrypted1, bob_shared_key)
    print(f"   Received: '{decrypted1}'\n")
    
    # Bob replies
    print("👨 Bob: Encrypting reply...")
    message2 = "Hey Alice! Our chat is secure now! 🔒"
    encrypted2 = encrypt_symmetric(message2, bob_shared_key)
    print(f"   Sent: {encrypted2[:40].hex()}... ({len(encrypted2)} bytes)\n")
    
    # Alice decrypts
    print("👩 Alice: Decrypting reply...")
    decrypted2 = decrypt_symmetric(encrypted2, alice_shared_key)
    print(f"   Received: '{decrypted2}'\n")
    
    # Summary
    print("=" * 70)
    print("HOW IT WORKS:")
    print("=" * 70)
    print("1. 🔧 Both agree on public parameters")
    print("2. 👤 Each generates private + public key")
    print("3. 🌐 They EXCHANGE public keys (anyone can see)")
    print("4. 🔑 Each combines THEIR private + OTHER's public = SAME shared key!")
    print("5. ⚡ Now use FAST symmetric encryption for all messages")
    print()
    print("WHY THIS IS BRILLIANT:")
    print("=" * 70)
    print("✅ No one else can compute the shared key (even if they see public keys)")
    print("✅ Asymmetric crypto ONCE, then fast symmetric crypto forever")
    print("✅ This is how HTTPS, Signal, WhatsApp, SSH work!")
    print("=" * 70)


if __name__ == "__main__":
    main()
