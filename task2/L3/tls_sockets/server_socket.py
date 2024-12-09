import socket
import threading
import json
from utils import *

SOCKET_PORT = 1700
clients = {}

secret_key, public_key = generate_ecdh_key_pair()
sk_ca , pk_ca = generate_server_ca_keys()

def perform_tls_handshake(client_socket, public_key, nonce):
    nonce = os.urandom(64)
    k1c, k1s = keySchedule1(secret_key.exchange(ec.ECDH(), ec.ECDH.PublicKey.from_encoded_point(ec.ECDH(), public_key)), nonce)
    
def handle_client(client_socket, client_address):
    while True:
        try:
            message = client_socket.recv(1024).decode('utf-8')
            print(message)
            if not message:
                break
            data = from_json(message)
            target_client = data['target']
            msg = data['msg']
            source_client = data['source']
            msg_type = data['type']
            nonce = data['nonce']
            
            if source_client not in clients.keys():
                if msg_type == "tls":
                    perform_tls_handshake(client_socket, msg, nonce)
                clients[source_client] = client_socket
            print(f"Received message: {msg} from {client_address} to {target_client}")
            if target_client in clients:
                print(f"Sending message to {target_client}")
                clients[target_client].send(f"Message from {client_address}: {msg}".encode('utf-8'))
            else:
                print(f"Client {target_client} not found.")
                client_socket.send(f"Client {target_client} not found.".encode('utf-8'), client_address)
        except:
            print(f"Client {client_address} disconnected")
            break
    client_socket.close()
    del clients[client_address]
    print(f"Client {client_address} disconnected")

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', SOCKET_PORT))
    server_socket.listen(5)
    print(f"Server listening on port {SOCKET_PORT}")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Client {client_address} connected")
        clients[client_address] = client_socket
        client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_handler.start()



if __name__ == "__main__":
    start_server()