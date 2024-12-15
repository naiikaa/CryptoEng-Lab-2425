import socket
import ssl
import threading
import hashlib
import os
import json
from utils import *

class Server:
    def __init__(self):
        self.server_address = ('localhost', 1717)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile='server.crt', keyfile='server.key')
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(self.server_address)
        self.sock.listen(5)
        self.ssock = self.context.wrap_socket(self.sock, server_side=True)
        print(f"Server listening on {self.server_address}")
        self.client_threads = []
        self.registered_clients = {}
        self.user_keybundles = {}
        
    def start(self):
        while True:
            client_socket, client_address = self.ssock.accept()
            print(f"Connection from {client_address}")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()
            self.client_threads.append(client_thread)

    def handle_register(self, client_socket, msg):
        username = msg['username']
        if username not in self.registered_clients:
            self.registered_clients[username] = client_socket
            self.user_keybundles[username] = msg['key_bundle']
            print(f"Registered {username} successfully with keybundle {msg['key_bundle']}")
            client_socket.sendall(f"Registered {username} successfully".encode('utf-8'))
        else:
            client_socket.sendall("Username already taken".encode('utf-8'))
            print(f"Username {username} tried to register again")
    
    def handle_x3dh(self, client_socket, msg):
        target = msg['target']
        if target in self.user_keybundles:
            target_keybundle = self.user_keybundles.get(target)
            payload = {"type": "x3dh", 
                        "username": target, 
                        "key_bundle": json.dumps(target_keybundle)}
            res = json.dumps(payload)
            client_socket.sendall(res.encode('utf-8'))
            print(f"Sent keybundle of {target} to {msg['username']}")
        else:
            client_socket.sendall(f"User {target} not found".encode('utf-8'))
            print(f"User {target} not found")
        
    def handle_client(self, client_socket):
        while True:
            try:
                msg = client_socket.recv(1024*8).decode('utf-8')
                if not msg:
                    break
                msg = json.loads(msg)
                type = msg['type']
                
                if type == "register":
                    self.handle_register(client_socket,msg)
                if type == "x3dh":
                    self.handle_x3dh(client_socket,msg)
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"Error handling client: {e}")
                break


if __name__ == "__main__":
    server = Server()
    server.start()