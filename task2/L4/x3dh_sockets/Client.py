import socket
import ssl
import threading
import hashlib
import os
import json
from utils import *


class X3DHClient:
    def __init__(self, ):
        self.username = input("Enter your username: ")
        self.server_address = ('localhost', 1717)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_verify_locations('server.crt')
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ssock = self.context.wrap_socket(self.sock, server_hostname='localhost')
        self.ik ,self.IPK  = generate_server_ca_keys()
        self.sk ,self.SPK = generate_server_ca_keys()
        self.ok ,self.OPK = generate_server_ca_keys()
        self.key_bundle_sign = ecdsa_sign(message=self.SPK.to_pem(),
                                          private_key=self.ik,nonce=b"")
        self.key_bundles = {}
        self.x3dh_sessions_keys = {}
        
        while True:
                try:
                    self.connect_to_server()
                    break
                except Exception as e:
                    print(f"Failed to connect to server: {e}")
                    print("Retrying in 2 seconds...")
                    time.sleep(2)

    def connect_to_server(self):
        try:
            self.ssock.connect(self.server_address)
            print(f"Connected to server at {self.server_address}")
            self.send_messages()
        except Exception as e:
            print(f"Failed to connect to server: {e}")
            self.ssock.close()
            
    def compute_shared_x3dh_key_inital(self):
        ek , EPK = generate_server_ca_keys()
        # DH1 = SPK ^ ik
        DH1 = self.SPK.pubkey
        # DH2 = IPK ^ ek
        # DH3 = SPK ^ ek
        # DH4 = OPK ^ ek
        # KDF(DH1,DH2,DH3,DH4)
    
    def  compute_shared_x3dh_key_reaction(self):
        # DH1 = IPK_A ^ sk
        # DH2 = EPK_A ^ ik
        # DH3 = EPK_A ^ sk
        # DH4 = EPK_A ^ ok
        # KDF(DH1,DH2,DH3,DH4)
        
    def register(self):
        payload = {"type": "register", 
                    "username": self.username,
                    "key_bundle": {
                    "IPK": self.IPK.to_pem().hex(), 
                    "SPK": self.SPK.to_pem().hex(), 
                    "OPK": self.OPK.to_pem().hex(),
                    "key_bundle_sign": self.key_bundle_sign.hex()}}
                        
        message = json.dumps(payload)
        self.ssock.sendall(message.encode('utf-8'))
        response = self.ssock.recv(1024*8).decode('utf-8')
        print(f"Got response: {response}\n")
        
    def perform_x3dh(self):
        target = input("Enter target username for x3dh: ")
        payload = {"type": "x3dh", 
                    "username": self.username, 
                    "target": target}
        self.ssock.sendall(json.dumps(payload).encode('utf-8'))
        response = self.ssock.recv(1024*8).decode('utf-8')
        response = json.loads(response)
        targets_key_bundle = json.loads(response['key_bundle'])
        print(f"Got {target} key bundle: {targets_key_bundle}")
        self.key_bundles[target] = targets_key_bundle
        if self.verify_key_bundle(targets_key_bundle):
            
            self.x3dh_sessions_keys[target] = self.compute_shared_x3dh_key()
            
        
    def verify_key_bundle(self, key_bundle):
        IPK = VerifyingKey.from_pem(bytes.fromhex(key_bundle['IPK']))
        SPK = VerifyingKey.from_pem(bytes.fromhex(key_bundle['SPK']))
        OPK = VerifyingKey.from_pem(bytes.fromhex(key_bundle['OPK']))
        key_bundle_sign = bytes.fromhex(key_bundle['key_bundle_sign'])
        if ecdsa_verify(key_bundle_sign, SPK.to_pem(), IPK):
            print("Key bundle verified")
            return True
        else:
            print("Key bundle verification failed")
            return False
    
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
                    elif message == "x3dh":
                        self.perform_x3dh()
                    else:
                        payload = {"type": "message", "username": self.username, "message": message}
                        message = json.dumps(payload)
                        self.ssock.sendall(message.encode('utf-8'))
                except Exception as e:
                    import traceback
                    traceback.print_exc()
                    print(f"Error sending message: {e}")
                    break
    
if __name__ == "__main__":
    X3DHClient()