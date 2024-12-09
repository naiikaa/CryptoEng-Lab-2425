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
from ecdsa import SigningKey, util # pip install ecdsa
import json

# Use the curve P256, also known as SECP256R1, see https://neuromancer.sk/std/nist/P-256
from ecdsa import NIST256p as CURVE  

HASH_FUNC = hashes.SHA256() # Use SHA256
hasher = sha256
KEY_LEN = 32 # 32 bytes

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
    sign = ecdsa_sign(hasher((nonce_c+X+nonce_s+Y+cert[1])).digest(),sk)
    return sign

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

sk_ca = SigningKey.generate(CURVE)
pk_ca = sk_ca.get_verifying_key()


def main():
    #1. Client samples keys and a {0,1}²⁵⁶ nonce_c
    x, X = generate_ecdh_key_pair()
    nonce_c = os.urandom(256)

    #2. Client sends pk_c and nonce_c to the server
    print("Hello from Client: "+str(nonce_c), X.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode())

    #3. Server samples keys and a {0,1}²⁵⁶ nonce_s
    y, Y = generate_ecdh_key_pair()
    nonce_s = os.urandom(256)
    k_1_c, k_1_s = keySchedule1(y.exchange(ec.ECDH(), X))

    #4 Server sends pk_s, nonce_s to the client
    print("Hello from Server: "+str(nonce_s), Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode())
    
    #5. Server generates signnature and mac using different key schedulers
    sign_ca = ecdsa_sign(Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),sk_ca)
    cert = (Y,sign_ca)

    sign_sk = SigningKey.generate(CURVE)
    sign_pk = sign_sk.get_verifying_key()

    sign = serverSignature(sign_sk,nonce_c,X.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),nonce_s,Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),cert)
    
    k_2_c, k_2_s = keySchedule2(nonce_c,X.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),nonce_s,Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),y.exchange(ec.ECDH(), X))
    mac_s = serverMac(k_2_s,nonce_c,X.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),nonce_s,Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),sign,sign_ca)
    k_3_c, k_3_s = keySchedule3(nonce_c,X.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),nonce_s,Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),y.exchange(ec.ECDH(), X),sign,sign_ca,mac_s)

    #6. Server sends cert,sign and mac to client encrypted with aes-gcm

    combinded = json.dumps({"cert":str(sign_ca), "sign":str(sign), "mac":str(mac_s)})
    iv, cipher, tag = aes_gcm_encrypt(k_1_s, combinded,Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
    print(b"Encrypted message from Server: "+iv,cipher,tag)

    #7. Client derives keys from scheduler 
    k_1_c_c , k_1_s_c = keySchedule1(x.exchange(ec.ECDH(), Y))
    assert k_1_c == k_1_c_c, "Shared secrets do not match for K1c!"
    assert k_1_s == k_1_s_c, "Shared secrets do not match! for K1s"
    k_2_c_c, k_2_s_c = keySchedule2(nonce_c,X.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),nonce_s,Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),x.exchange(ec.ECDH(), Y))
    assert k_2_c == k_2_c_c, "Shared secrets do not match for K2c!"
    assert k_2_s == k_2_s_c, "Shared secrets do not match! for K2s"

    #8. Client decrypts the message from server
    message = aes_gcm_decrypt(k_1_s,iv,cipher,Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),tag)
    print("Decrypted message from Server: "+message)
    
    parts = json.loads(message)
    
    
    cert_2 = parts["cert"]
    cert_2 = cert_2[2:-1].encode().decode('unicode_escape').encode('ISO-8859-1')
    
    sign_2 = parts["sign"]
    sign_2 = sign_2[2:-1].encode().decode('unicode_escape').encode('ISO-8859-1')

    mac_2 = parts["mac"]
    mac_2 = mac_2[2:-1].encode().decode('unicode_escape').encode('ISO-8859-1')


    #9. Client verifies the signature and mac and cert
    
    # Check certificate validity and sanity checks
    assert sign_ca == cert_2, (sign_ca,cert_2)
    assert ecdsa_verify(sign_ca,Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),pk_ca), "Certificate is not valid"
    assert ecdsa_verify(cert_2,Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),pk_ca), "Certificate is not valid"
    
    # Check signature validity and sanity checks
    assert sign == sign_2, (sign,sign_2)
    hash = hasher(nonce_c+X.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)+nonce_s+Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)+cert_2).digest()
    assert ecdsa_verify(sign,hash,sign_pk), "Signature is not valid"
    assert ecdsa_verify(sign_2,hash,sign_pk), "Signature is not valid"
    # Check MAC validity and sanity checks
    assert mac_2 == mac_s, (mac_2,mac_s)
    mac_s_c = serverMac(k_2_s,nonce_c,X.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),nonce_s,Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),sign_2,cert_2)
    assert mac_2 == mac_s_c, (mac_2,mac_s_c)

    #10. Client computes final keys
    k_3_c_c, k_3_s_c = keySchedule3(nonce_c,X.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),nonce_s,Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),x.exchange(ec.ECDH(), Y),sign_2,cert_2,mac_2)
    assert k_3_c == k_3_c_c, "Shared secrets do not match for K3c!"
    assert k_3_s == k_3_s_c, "Shared secrets do not match! for K3s"

    #11. Client computes mac and sends it to the server
    mac_c = clientMac(k_2_c,nonce_c,X.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),nonce_s,Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),sign_2,cert_2)
    iv_mac, enc_mac_c,tag_mac = aes_gcm_encrypt(k_1_c_c,str(mac_c),Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
    print("Encrypted MAC from Client: ",iv_mac,enc_mac_c,tag_mac)

    #12. Server verifies the mac
    mac_c_d = aes_gcm_decrypt(k_1_c,iv_mac,enc_mac_c,Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),tag_mac)
    mac_c_d = mac_c_d[2:-1].encode().decode('unicode_escape').encode('ISO-8859-1')
    assert mac_c == mac_c_d, (mac_c,mac_c_d)

    print("TLS handshake completed successfully")

if __name__ == "__main__":
    main()