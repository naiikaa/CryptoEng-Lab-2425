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
               "nonce": decode_correctly(nonce_c),
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
            print(message)

            iv = encode_correctly(msg['iv'])
            cipher = encode_correctly(msg['cipher'])
            tag = msg['tag'].encode()
            nonce = encode_correctly(nonce)
            k_1_c, k_1_s = keySchedule1(secrect_key.exchange(ec.ECDH(), Y))
            
            k_2_c, k_2_s = keySchedule2(nonce_c,public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),nonce,Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),secrect_key.exchange(ec.ECDH(), Y))
            decrypted_msg = aes_gcm_decrypt(k_1_c, iv,cipher, Y.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),tag)
            print(decrypted_msg)
            
            
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
    while conn_to_peer is None:
        try:
            conn_to_peer = socket.create_connection(('localhost', SERVER_PORT),source_address=('localhost', OWN_PORT))
        except ConnectionRefusedError:
            print(f"{IDENTITY}: Waiting for SERVER to be online...")
            time.sleep(2)

    # Start a thread to listen for incoming messages
    listener_thread = threading.Thread(target=listen_for_messages, args=(conn_to_peer,))
    listener_thread.daemon = True
    listener_thread.start()
     
    tls_hello(conn_to_peer, public_key)


    # Send messages
    #sending_loop(conn_to_peer)
    while True:
        pass
    
if __name__ == "__main__":
    main()