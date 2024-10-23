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

def compute_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

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

def main():
    # Step 1: Keypairs for Alice and Bob
    x, X = generate_ecdh_key_pair() 

    # Step 2: Bob computes the Key and encrypts a message with it
    y, Y = generate_ecdh_key_pair() 
    c0 = Y

    X_y = y.exchange(ec.ECDH(), X)

    Y_bytes = Y.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    K_a = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=Y_bytes,
        info=b'handshake data',
    ).derive(X_y)

    message = "This is a fun message"

    nonce, c1 = aes_ctr_encrypt(K_a, message)

    send_msg = (c0,c1,nonce)

    # Step 3: Alice decrypts the message
    c0, c1, nonce = send_msg

    c0_bytes = c0.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    K_b = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=c0_bytes,
        info=b'handshake data',
    ).derive(x.exchange(ec.ECDH(), c0))

    recieved_message = aes_ctr_decrypt(K_b, nonce, c1)

    print("The transmission was:",recieved_message == message, recieved_message)

    
if __name__ == "__main__":
    main()