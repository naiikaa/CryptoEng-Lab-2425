from utils import *
import os

def xor(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

def iter_hash_with_salt(pw, salt, num_iter):
    hashlist = []
    padded_salt = salt + b'\x00' * 3 + b'\x01'
    hash_val = hmac_sign(pw, padded_salt)
    for i in range(num_iter - 1):
        hash_add = hmac_sign(pw, hash_val)
        hash_val = xor(hash_val, hash_add)
    return [salt, num_iter, hash_val]

if __name__ == '__main__':
    #init vars
    pw = os.urandom(32)
    salt = os.urandom(32)
    num_iter = 4096
    pw_file = iter_hash_with_salt(pw, salt, num_iter)
    
    #Client has pw and requests the server
    print("Client: Hey Server, I have the pw. Challange me!")
    
    #Server responds by sending salt and num_iter aswell as a challange that is uniformly sampled
    print("Server: Here is the salt, num_iter and the challange")
    print("salt: ", pw_file[0])
    print("num_iter: ", pw_file[1])
    #TODO how is ch2 generated?
    
    #Client computes the response to the challange
    salted_pw = iter_hash_with_salt(pw, pw_file[0], pw_file[1])
    client_key = hmac_sign(salted_pw, 'Client key')
    auth_msg = b'Bob'+pw_file[0]+b','+pw_file[1]+','+ch2
    client_sig = hmac_sign(hmac_sign(client_key,b''), auth_msg)
    client_proof = xor(client_key, client_sig)
    print("Client: Here is my proof: ", client_proof)
    
    #Server verifies the proof
 