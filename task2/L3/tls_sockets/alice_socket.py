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

def tls_hello(sock, public_key):
    nonce = os.urandom(64)

    payload = {"target": "server",
               "nonce": str(nonce),
                "msg": public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
                "source": IDENTITY,
                "type": "tls"
    }
    msg = json.dumps(payload)
    sock.sendto(msg.encode(), server_address)
    

def listen_for_messages(sock):
    while True:
        message, addr = sock.recvfrom(1024)
        if message == b'':
            continue
        #unpack message
        data = from_json(message)
        target_client = data['target']
        msg = data['msg']
        source_client = data['source']
        msg_type = data['type']
        nonce = data['nonce']
        if msg_type == 'msg':
            print(f"Received message: {message.decode()} from {addr}")
        if msg_type == 'tls':
            print(f"Received TLS message from {addr}")
            
        
        


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


    # Perform TLS handshake
    while not tls_done:
        try:
            tls_hello(conn_to_peer, public_key)
            time.sleep(2)
        except:
            print("Something went wrong during TLS handshake")
            time.sleep(5)
        


    # Send messages
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

if __name__ == "__main__":
    main()