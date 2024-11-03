from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Cryptodome.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os, hashlib

# Generate ECDH private and public key pair
def generate_ecdh_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

# Compute the shared secret using ECDH
def compute_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

# HKDF to derive symmetric key from shared secret
def derive_key_from_shared_secret(shared_secret, salt=None, info=b"handshake data"):
    if salt is None:
        salt = os.urandom(16)
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # AES-256 key size
        salt=salt,
        info=info,
    ).derive(shared_secret)
    return derived_key

# Symmetric Encryption (AES-CTR)
def aes_ctr_encrypt(derived_key, plaintext):
    cipher = AES.new(derived_key, AES.MODE_CTR)
    nonce = cipher.nonce  # CTR mode uses a nonce instead of an IV
    ciphertext = cipher.encrypt(plaintext.encode())  # No padding needed in CTR
    return nonce, ciphertext

# Symmetric Decryption (AES-CTR)
def aes_ctr_decrypt(derived_key, nonce, ciphertext):
    cipher = AES.new(derived_key, AES.MODE_CTR, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode()

# AES-GCM encryption
def aes_gcm_encrypt(key, plaintext, associated_data):
    iv = os.urandom(12)  # GCM mode standard IV size is 96 bits (12 bytes)
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    ).encryptor()

    # Add associated data (not encrypted but authenticated)
    encryptor.authenticate_additional_data(associated_data)

    # Encrypt the plaintext
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    return iv, ciphertext, encryptor.tag

# AES-GCM decryption
def aes_gcm_decrypt(key, iv, ciphertext, associated_data, tag):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    ).decryptor()

    # Add associated data (must match what was provided during encryption)
    decryptor.authenticate_additional_data(associated_data)

    # Decrypt the ciphertext
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext.decode()

# Main function
def main():
    # Step 1: Generate ECDH key pairs for Alice and Bob
    x, X = generate_ecdh_key_pair() # Alice has (x, X = g^x)
    y, Y = generate_ecdh_key_pair() # Bob has (y, Y = g^y)

    # Step 2: The evil actor in the middle creates key pairs for alice and bob
    # and exchanges the public keys
    x_mitm, X_mitm = generate_ecdh_key_pair()
    y_mitm, Y_mitm = generate_ecdh_key_pair()

    # Step 3: Compute shared secret using ECDH
    K_Bob = compute_shared_secret(y, X_mitm) # Bob computes X'^y
    K_Bob_mitm = compute_shared_secret(x_mitm, Y) # MitM computes Y^x'

    K_Alice_mitm = compute_shared_secret(y_mitm, X) # MitM computes X^y'
    K_Alice = compute_shared_secret(x, Y_mitm) # Alice computes Y'^x

    assert K_Alice == K_Alice_mitm, "Shared secrets with Alice do not match!"
    assert K_Bob == K_Bob_mitm, "Shared secrets with Bob do not match!"

    # Step 4: Derive symmetric keys from shared secrets
    salt = bytes([0] * hashlib.sha256().digest_size)

    derived_K_Alice = derive_key_from_shared_secret(K_Alice, salt)
    derived_K_Bob = derive_key_from_shared_secret(K_Bob, salt)
    derived_K_Alice_mitm = derive_key_from_shared_secret(K_Alice_mitm, salt)
    derived_K_Bob_mitm = derive_key_from_shared_secret(K_Bob_mitm, salt)

    # Step 5: Encrypt a message and send it (Alice -> MitM)
    message = "This is a fun message"
    associated_data = f"Alice, Bob, {X}, {Y}".encode() # Set the assiciate data as "('Alice', 'Bob', A, B)", where A and B are the pk's of ALice and Bob, respectively
    iv, ciphertext, tag = aes_gcm_encrypt(derived_K_Alice, message, associated_data=associated_data)
    print(f"Alice: Sending message to MitM: {ciphertext}")

    # Step 6: Decrypt the message, read it and send it to Bob (MitM -> Bob)
    plaintext_mitm = aes_gcm_decrypt(derived_K_Alice_mitm, iv, ciphertext, associated_data, tag)
    print(f"MitM: Received message from Alice: {plaintext_mitm}")
    iv , ciphertext, tag = aes_gcm_encrypt(derived_K_Bob_mitm, plaintext_mitm, associated_data=associated_data)
    print(f"MitM: Sending message to Bob: {ciphertext}")

    # Step 7: Decrypt the message and read it (Bob)
    plaintext_bob = aes_gcm_decrypt(derived_K_Bob, iv, ciphertext, associated_data, tag)
    print(f"Bob: Received message from MitM: {plaintext_bob}")
    print("Did MitM and Bob decrypt the same message?: ",plaintext_bob == plaintext_mitm)
    print("Did Bob recieve the same message as Alice sent out?: ",plaintext_bob == message)



if __name__ == "__main__":
    main()
