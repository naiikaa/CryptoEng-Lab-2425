import socket
import threading
import json
import time
from utils import *

SERVER_PORT = 1700
IDENTITY = "Alice"
OWN_PORT = 1717
tls_done = False
server_address = ('localhost', SERVER_PORT)

secrect_key, public_key = generate_ecdh_key_pair()
shared_key = None  
Y = None
nonce_c = os.urandom(64)

def tls_hello(sock, public_key):
    payload = {"target": "server",
               "nonce": nonce_c.hex(),
                "msg": public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
                "source": IDENTITY,
                "type": "tls-0"
    }
    msg = json.dumps(payload)
    sock.sendto(msg.encode('utf-8'), server_address) 
    

def listen_for_messages(sock):
    while True:
        message, addr = sock.recvfrom(1024*8)
        if message == b'':
            break
        #unpack message
        data = from_json(message)
        target_client = data['target']
        msg = data['msg']
        source_client = data['source']
        msg_type = data['type']
        nonce = data['nonce']
        if msg_type == 'msg':
            print(f"Received message: {message.decode()} from {addr}")
        if msg_type == 'tls-1':
            Y = serialization.load_pem_public_key(msg.encode('utf-8'))
            print(message)
        if msg_type == 'tls-2':
      
            iv = bytes.fromhex(msg['iv'])
            cipher = bytes.fromhex(msg['cipher'])
            tag = bytes.fromhex(msg['tag'])
            nonce_s = bytes.fromhex(nonce)
            k_1_c, k_1_s = keySchedule1(secrect_key.exchange(ec.ECDH(), Y))
            
            k_2_c, k_2_s = keySchedule2(nonce_c,public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),nonce_s,Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),secrect_key.exchange(ec.ECDH(), Y))
            decrypted_msg = aes_gcm_decrypt(k_1_s, iv,cipher, Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),tag)
            print(f"Decrypted message: {decrypted_msg}")  
            
            decrypted_json = json.loads(decrypted_msg)
            cert = json.loads(decrypted_json['cert'])
            sign = bytes.fromhex(decrypted_json['sign'])
            mac = bytes.fromhex(decrypted_json['mac'])
            pk_ca = VerifyingKey.from_pem(bytes.fromhex(cert['public_key_certificate']))
            pk_sign = VerifyingKey.from_pem(bytes.fromhex(decrypted_json['pk_sign']))
            sign_ca = bytes.fromhex(cert['signature'])
            assert ecdsa_verify(sign_ca,Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo), pk_ca)
            hash = hasher(nonce_c+public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)+nonce_s+Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)+encode_correctly(json.dumps(cert))).digest()
            assert ecdsa_verify(sign,hash,pk_sign)
            assert mac == serverMac(k_2_s,nonce_c,public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),nonce_s,Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),sign,sign_ca)
            
            k_3_c, k_3_s = keySchedule3(nonce_c,public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),nonce_s,Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),secrect_key.exchange(ec.ECDH(), Y),sign,sign_ca,mac)
            mac_c = clientMac(k_2_c,nonce_c,public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),nonce_s,Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),sign,sign_ca)
            iv_mac , cipher_mac, tag_mac = aes_gcm_encrypt(k_1_c, mac_c.hex(),public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
            encrypted_msg ={"iv":iv_mac.hex(), "cipher":cipher_mac.hex(), "tag":tag_mac.hex()}
            encrypted_msg = json.dumps(encrypted_msg)
            payload = {"target": "server",
               "nonce": nonce_c.hex(),
                "msg": encrypted_msg,
                "source": IDENTITY,
                "type": "tls-3"
            }
            sock.sendall(json.dumps(payload).encode('utf-8'))
            response = sock.recv(1024*8)
            print(b"Got response: "+response)
            
def sending_loop(conn_to_peer):
    while True:
        message = input("Enter message to send: ")
        if message.lower() == 'exit':
            break
        target = input("Enter target client: ")
        payload = {
            "target": target,
            "msg": message,
            "source": IDENTITY
        }
        msg = json.dumps(payload)
        conn_to_peer.sendto(msg.encode(), server_address)       
        


def main():
    # Try connecting to the server
    print(f"{IDENTITY}: Try connecting to SERVER...")
    conn_to_peer = None
    while True:
        try:
            #check if socket already in use and close first
            conn_to_peer = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn_to_peer.connect(server_address)
            break
        except Exception as e:
            print(f"{IDENTITY}: Waiting for SERVER to be online...")
            time.sleep(2)

    # Start a thread to listen for incoming messages
    listener_thread = threading.Thread(target=listen_for_messages, args=(conn_to_peer,))
    listener_thread.daemon = True
    listener_thread.start()
    try:
        tls_hello(conn_to_peer, public_key)
    except Exception as e:
        print(f"Error: {e}")
        conn_to_peer.close()
        return


    # Send messages
    #sending_loop(conn_to_peer)
    while True:
        pass
    
if __name__ == "__main__":
    main()