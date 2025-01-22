import socket
import ssl
import threading
import hashlib
import os
import json
from utils import *
import time


class Client:
    def __init__(self, ):
        self.username = input("Enter your username: ")
        self.server_address = ('localhost', 7777)
        self.sk ,self.PK  = generate_server_ca_keys()
        self.string_pk = self.PK.to_pem().hex()
        self.shared_keys = {}

        while True:
                try:
                    self.connect_to_server()
                    break
                except Exception as e:
                    print(f"Failed to connect to server.")
                    print("Retrying in 2 seconds...")
                    time.sleep(2)

    def connect_to_server(self):
        try:
            self.ssock = socket.create_connection(self.server_address)
            print(f"Connected to server at {self.server_address}")
            #sending thread
            self.send_thread = threading.Thread(target=self.send_messages)
            self.send_thread.start()
            #listening thread
            self.listen_thread = threading.Thread(target=self.handle_messages)
            self.listen_thread.start()    
        except Exception as e:
            print(f"Failed to connect to server: {e}")
            self.ssock.close()
    
    def register(self):
        payload = {"type": "register", "username": self.username}
        message = json.dumps(payload)
        self.ssock.sendall(message.encode('utf-8'))

    def init_dhke(self,target):
        payload = {"type": "dhke_init", "username": self.username, "target":target, "public_key": self.string_pk}
        message = json.dumps(payload)
        self.ssock.sendall(message.encode('utf-8'))

    def react_dhke(self, target):
        payload = {"type": "dhke_react", "username": self.username, "target":target, "public_key": self.string_pk}
        message = json.dumps(payload)
        self.ssock.sendall(message.encode('utf-8'))

    def send_messages(self):
        while True:
            message = input("Enter message: ")
            if message:
                try:
                    if message == "exit":
                        self.ssock.close()
                        break
                    elif message == "register":
                        self.register()
                    elif message == "dhke":
                        target = input("Enter target user: ")
                        self.init_dhke(target)                       
                    else:
                        payload = {"type": "message", "username": self.username, "message": message}
                        message = json.dumps(payload)
                        self.ssock.sendall(message.encode('utf-8'))
                except Exception as e:
                    import traceback
                    traceback.print_exc()
                    print(f"Error sending message: {e}")
                    break
    
    def handle_dhke_init(self, message):
        target = message['username']
        public_key = message['public_key']
        public_key = VerifyingKey.from_pem(bytes.fromhex(public_key))

        sk_ecdh = ECDH(CURVE)
        sk_ecdh.load_private_key(self.sk)
        sk_ecdh.load_received_public_key_pem(public_key.to_pem())
        shared_key = sk_ecdh.generate_sharedsecret_bytes()
        
        self.shared_keys[target] = shared_key
        print(f"Received DHKE init from {target}")
        self.react_dhke(target)
        print(f"DHKE with {target} successful.")
        print(f"Shared key with {target}: {shared_key}")

    def handle_dhke_react(self, message):
        target = message['username']
        public_key = message['public_key']
        public_key = VerifyingKey.from_pem(bytes.fromhex(public_key))

        sk_ecdh = ECDH(CURVE)
        sk_ecdh.load_private_key(self.sk)
        sk_ecdh.load_received_public_key_pem(public_key.to_pem())
        shared_key = sk_ecdh.generate_sharedsecret_bytes()

        self.shared_keys[target] = shared_key
        print(f"Received DHKE reaction from {target}")
        print(f"DHKE with {target} successful.")
        print(f"Shared key with {target}: {shared_key}")
        

    def handle_messages(self):
        while True:
            try:
                message = self.ssock.recv(1024*8).decode('utf-8')
                if not message:
                    break
                message = json.loads(message)
                type = message['type']
                
                if type == "server_message":
                    print(f"Message from Server: {message['message']}")
                
                if type == "dhke_init":
                    self.handle_dhke_init(message)
                
                if type == "dhke_react":
                    self.handle_dhke_react(message)
                    
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"Error handling message: {e}")
                break
if __name__ == "__main__":
    Client()