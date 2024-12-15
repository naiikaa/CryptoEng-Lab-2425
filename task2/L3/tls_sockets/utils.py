
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend
from ecdsa import util # pip install ecdsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from Cryptodome.Cipher import AES
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
from hashlib import sha256
from ecdsa import SigningKey, util, VerifyingKey # pip install ecdsa
import json

# Use the curve P256, also known as SECP256R1, see https://neuromancer.sk/std/nist/P-256
from ecdsa import NIST256p as CURVE  

HASH_FUNC = hashes.SHA256() # Use SHA256
hasher = sha256
KEY_LEN = 32 # 32 bytes

def from_json(message):
    return json.loads(message)

def generate_ecdh_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

# HKDF.Extract
def hkdf_extract(salt, input_key_material, length=KEY_LEN):
    # Extract: Derive the PRK (pseudorandom key)
    hkdf_extract = HKDF(
        algorithm=HASH_FUNC,
        length=length,             # Length of the PRK (match SHA-256 output: 32 bytes)
        salt=salt,             # Salt can be any value or None
        info=None,             # No info for Extract phase
        backend=default_backend()
    )
    prk = hkdf_extract.derive(input_key_material)
    return prk

# HKDF.Expand
def hkdf_expand(prk, info, length=KEY_LEN):
    # Expand: Derive the final key from the PRK
    hkdf_expand = HKDF(
        algorithm=HASH_FUNC,
        length=length,         # Desired output length of the final derived key
        salt=None,             # No salt in the Expand phase (PRK is used directly as key)
        info=info,             # Context-specific info parameter
        backend=default_backend()
    )
    derived_key = hkdf_expand.derive(prk)
    return derived_key

# HMAC_Sign
def hmac_sign(key, message): # compute tag = HMAC(key, message)
    # Create an HMAC object using SHA-256
    h = hmac.HMAC(key, HASH_FUNC, backend=default_backend())
    h.update(message)
    tag = h.finalize()
    # Generate the HMAC code (digest)
    return tag

# HMAC_Verify
def hmac_verify(key, message, tag): # Verify tag =? HMAC(key, message)
    # Create a new HMAC object with the same message and key
    h = hmac.HMAC(key, HASH_FUNC, backend=default_backend())
    h.update(message)
    try:
        # Verify by comparing with the provided signature
        h.verify(tag)
        return True
    except Exception:
        return False
    

# Function to sign a message using ECDSA
def ecdsa_sign(message, private_key, nonce = None):
    signature = None
    if nonce: # If the nonce is explicitly specified
        signature = private_key.sign(
            message,
            k=nonce, 
            hashfunc=hasher, 
            sigencode=util.sigencode_der
        )
    else:
        signature = private_key.sign(
            message,
            hashfunc=hasher, 
            sigencode=util.sigencode_der
        )
    return signature


# Function to verify ECDSA signature
def ecdsa_verify(signature, message, public_key):
    try:
        is_valid = public_key.verify(
            signature,
            message,
            hashfunc=hasher,
            sigdecode=util.sigdecode_der
        )
        return is_valid
    except:
        return False

def deriveHS(g_xy):
    es = hkdf_extract(bytes([0] * 32),bytes([0] * 32))
    dES = hkdf_expand(es, hasher(b"DerivedES").digest())
    hs = hkdf_extract(dES, hasher(g_xy).digest())
    return hs

def keySchedule1(g_xy):
    hs = deriveHS(g_xy)
    k_1_c = hkdf_expand(hs, hasher(b"ClientKE").digest())
    k_1_s = hkdf_expand(hs, hasher(b"ServerKE").digest())
    return k_1_c, k_1_s

def keySchedule2(nonce_c,X,nonce_s,Y,g_xy):
    hs = deriveHS(g_xy)
    ClientKC = hasher((str(nonce_c)+X+str(nonce_s)+Y+"ClientKC").encode()).digest()
    ServerKC = hasher((str(nonce_c)+X+str(nonce_s)+Y+"ServerKC").encode()).digest()
    k_2_c = hkdf_expand(hs, ClientKC)
    k_2_s = hkdf_expand(hs, ServerKC)
    return k_2_c, k_2_s

def printType(vars):
    for var in vars:
        print(type(var))

def keySchedule3(nonce_c,X,nonce_s,Y,g_xy,sign,cert,mac_s):
    #printType([nonce_c,X,nonce_s,Y,g_xy,sign,cert,mac_s])
    hs = deriveHS(g_xy)
    dHS = hkdf_expand(hs, hasher(b"DerivedHS").digest())
    MS = hkdf_expand(dHS, bytes([0] * 32))
    ClientSKH = hasher((nonce_c+X+nonce_s+Y+sign+cert+mac_s+b"ClientEncK")).digest()
    ServerSKH = hasher((nonce_c+X+nonce_s+Y+sign+cert+mac_s+b"ServerEncK")).digest()
    k_3_c = hkdf_expand(MS, ClientSKH)
    k_3_s = hkdf_expand(MS, ServerSKH)
    return k_3_c, k_3_s

def serverSignature(sk,nonce_c,X,nonce_s,Y,cert):
    
    sign = ecdsa_sign(hasher((nonce_c+X+nonce_s+Y+encode_correctly(cert))).digest(),sk)

    return sign

def encode_correctly(data):
    return data.encode().decode('unicode_escape').encode('ISO-8859-1')

def decode_correctly(data):
    return data.decode('unicode_escape')

def str_correctly(data):
    return str(data).decode('unicode_escape').encode('ISO-8859-1')

def serverMac(k_2_s,nonce_c,X,nonce_s,Y,sign,cert):
    mac_s = hmac_sign(k_2_s,hasher(nonce_c+X+nonce_s+Y+sign+cert+b"ServerMAC").digest())
    return mac_s

def clientMac(k_2_c,nonce_c,X,nonce_s,Y,sign,cert):
    mac_c = hmac_sign(k_2_c,hasher(nonce_c+X+nonce_s+Y+sign+cert+b"ClientMAC").digest())
    return mac_c

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

def generate_server_ca_keys():
    sk_ca = SigningKey.generate(CURVE)
    pk_ca = sk_ca.get_verifying_key()
    return sk_ca, pk_ca