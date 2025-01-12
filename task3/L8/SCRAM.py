from utils import *
import os
import random
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
    ch2 = os.urandom(32)
    print("salt: ", pw_file[0])
    print("num_iter: ", pw_file[1])
    print("challange: ", ch2)
    
    
    #Client computes the response to the challange
    salted_pw = iter_hash_with_salt(pw, pw_file[0], pw_file[1])[2]
    client_key = hmac_sign(salted_pw, b'Client key')
    auth_msg = b'Bob'+pw_file[0]+b','+pw_file[1].to_bytes(8,'big')+b','+ch2
    client_sig = hmac_sign(hmac_sign(client_key,b''), auth_msg)
    client_proof = xor(client_key, client_sig)
    print("Client: Here is my proof: ", client_proof)
    
    #Server verifies the proof
    client_key_server = hmac_sign(pw_file[2], b'Client key')
    auth_msg_server = b'Bob'+pw_file[0]+b','+pw_file[1].to_bytes(8,'big')+b','+ch2
    client_sig_server = hmac_sign(hmac_sign(client_key_server,b''), auth_msg_server)
    client_proof_server = xor(client_key_server, client_sig_server)
    assert client_proof_server == client_proof 
    print("Server: Proof verified. Welcome Bob!")
    
    #Client now challanges the server
    ch1 = os.urandom(32)
    print("Client: Here is my challange: ", ch1)
    
    #Server computes the response to the challange
    salted_pw_server = iter_hash_with_salt(pw, pw_file[0], pw_file[1])
    server_key = hmac_sign(salted_pw, b'Server key')
    auth_msg_server = b'Bob'+ch1
    server_sign = hmac_sign(server_key, auth_msg_server)
    print("Server: Here is my proof: ", server_sign)
    
    #Client verifies the proof
    server_key_client = hmac_sign(salted_pw, b'Server key')
    auth_msg_client = b'Bob'+ch1
    server_sign_client = hmac_sign(server_key_client, auth_msg_client)
    assert server_sign_client == server_sign
    print("Client: Proof verified. Welcome Server!")
    
    print("Task completed successfully")
    
 