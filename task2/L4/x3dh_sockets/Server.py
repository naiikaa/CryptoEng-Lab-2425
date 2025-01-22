import socket
import ssl
import threading
import hashlib
import os
import json
from utils import *

class Server:
    def __init__(self):
        self.server_address = ('localhost', 7777)
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
        self.x3dh_forward_waitlist = {}
        
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
            client_socket.sendall(json.dumps({"type": "server_message", "message": "Register succesfull"}).encode('utf-8'))
            if username in self.x3dh_forward_waitlist:
                self.forward_x3dh_reaction(client_socket, self.x3dh_forward_waitlist[username])
                del self.x3dh_forward_waitlist[username]
        else:
            client_socket.sendall(json.dumps({"type": "server_message", "message": "Register failed. Already registered"}).encode('utf-8'))
            print(f"Username {username} tried to register again")
    
    def handle_x3dh(self, client_socket, msg):
        target = msg['target']
        username = msg['username']
        if target in self.user_keybundles:
            target_keybundle = self.user_keybundles.get(target)
            payload = {"type": "x3dh", 
                        "username": username,
                        "target": target,
                        "key_bundle": json.dumps(target_keybundle)}
            res = json.dumps(payload)
            client_socket.sendall(res.encode('utf-8'))
            print(f"Sent keybundle of {target} to {msg['username']}")
        else:
            client_socket.sendall(json.dumps({"type": "server_message", "message": "X3DH Protocol. User not found."}).encode('utf-8'))
            print(f"User {target} not found")
    
    def forward_x3dh_reaction(self, client_socket, msg):
        target = msg['target']
        if target in self.registered_clients:
            target_socket = self.registered_clients.get(target)
            target_socket.sendall(json.dumps(msg).encode('utf-8'))
            client_socket.sendall(json.dumps({"type": "server_message", "message": "Forwarded x3dh reaction to target."}).encode('utf-8'))
            print(f"Forwarded x3dh reaction to {target}")
        else:
            self.x3dh_forward_waitlist[target] = msg
            client_socket.sendall(json.dumps({"type": "server_message", "message": "User not registered yet will forward when online."}).encode('utf-8'))
            print(f"User {target} not found. Hold on wait until online")
    
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
                    
                if type == "x3dh_reaction":
                    self.forward_x3dh_reaction(client_socket,msg)
                    
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"Error handling client: {e}")
                break


if __name__ == "__main__":
    server = Server()
    server.start()