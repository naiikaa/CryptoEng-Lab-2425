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
        self.ssock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ssock.bind(self.server_address)
        self.ssock.listen(5)
        print(f"Server listening on {self.server_address}")
        self.client_threads = []
        self.registered_clients = {}
        
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
            print(f"Registered {username} successfully.")
            client_socket.sendall(json.dumps({"type": "server_message", "message": "Register succesfull"}).encode('utf-8'))
        else:
            client_socket.sendall(json.dumps({"type": "server_message", "message": "Register failed. Already registered"}).encode('utf-8'))
            print(f"Username {username} tried to register again")
    
    def handle_dhke(self, client_socket, msg):
        username = msg['username']
        target = msg['target']
        if target not in self.registered_clients:
            client_socket.sendall(json.dumps({"type": "server_message", "message": "DHKE failed. Target not registered"}).encode('utf-8'))
            print(f"Username {username} tried to initiate DHKE without registering")
        if target in self.registered_clients:
            target_socket = self.registered_clients[target]
            target_socket.sendall(json.dumps(msg).encode('utf-8'))
            print(f"Forwarding DHKE message from {username} to {target}")


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
                
                if type == "dhke_init" or type == "dhke_react":
                    self.handle_dhke(client_socket, msg)
                    
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"Error handling client: {e}")
                break


if __name__ == "__main__":
    server = Server()
    server.start()