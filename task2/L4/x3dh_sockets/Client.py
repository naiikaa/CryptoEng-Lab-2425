import socket
import ssl
import threading
import hashlib
import os
import json
from utils import *
import time


class X3DHClient:
    def __init__(self, ):
        self.username = input("Enter your username: ")
        self.server_address = ('localhost', 7777)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_verify_locations('server.crt')
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
                    print(f"Failed to connect to server.")
                    print("Retrying in 2 seconds...")
                    time.sleep(2)

    def connect_to_server(self):
        try:
            self.sock = socket.create_connection(self.server_address)
            self.ssock = self.context.wrap_socket(self.sock, server_hostname='localhost')
            print(f"Connected to server at {self.server_address}")
            #sending thread
            self.send_thread = threading.Thread(target=self.send_messages)
            self.send_thread.start()
            #listening thread
            self.listen_thread = threading.Thread(target=self.handle_messages)
            self.listen_thread.start()    

            self.register()
        except Exception as e:
            print(f"Failed to connect to server: {e}")
            self.ssock.close()
            
    def compute_shared_x3dh_key_inital(self,target):
        ek , EPK = generate_server_ca_keys()
        # DH1 = SPK_B ^ ik
        ik_ecdh = ECDH(CURVE)
        ik_ecdh.load_private_key(self.ik)
        ik_ecdh.load_received_public_key_pem(bytes.fromhex(self.key_bundles[target]['SPK']))
        DH1 = ik_ecdh.generate_sharedsecret_bytes()
        # DH2 = IPK_B ^ ek
        ek_ecdh = ECDH(CURVE)
        ek_ecdh.load_private_key(ek)
        ek_ecdh.load_received_public_key_pem(bytes.fromhex(self.key_bundles[target]['IPK']))
        DH2 = ek_ecdh.generate_sharedsecret_bytes()
        # DH3 = SPK_B ^ ek
        ek_ecdh.load_received_public_key_pem(bytes.fromhex(self.key_bundles[target]['SPK']))
        DH3 = ek_ecdh.generate_sharedsecret_bytes()
        # DH4 = OPK_B ^ ek
        ek_ecdh.load_received_public_key_pem(bytes.fromhex(self.key_bundles[target]['OPK']))
        DH4 = ek_ecdh.generate_sharedsecret_bytes()
        # KDF(DH1,DH2,DH3,DH4)
        shared_key = hkdf_extract(salt=None, input_key_material=DH1+DH2+DH3+DH4)
        
        return shared_key, ek, EPK
    
    def  compute_shared_x3dh_key_reaction(self,IPK_A,EPK_A):
        # DH1 = IPK_A ^ sk
        sk_ecdh = ECDH(CURVE)
        sk_ecdh.load_private_key(self.sk)
        sk_ecdh.load_received_public_key_pem(IPK_A.to_pem())
        DH1 = sk_ecdh.generate_sharedsecret_bytes()
        # DH2 = EPK_A ^ ik
        ik_ecdh = ECDH(CURVE)
        ik_ecdh.load_private_key(self.ik)
        ik_ecdh.load_received_public_key_pem(EPK_A.to_pem())
        DH2 = ik_ecdh.generate_sharedsecret_bytes()
        # DH3 = EPK_A ^ sk
        sk_ecdh.load_received_public_key_pem(EPK_A.to_pem())
        DH3 = sk_ecdh.generate_sharedsecret_bytes()
        # DH4 = EPK_A ^ ok
        ok_ecdh = ECDH(CURVE)
        ok_ecdh.load_private_key(self.ok)
        ok_ecdh.load_received_public_key_pem(EPK_A.to_pem())
        DH4 = ok_ecdh.generate_sharedsecret_bytes()
        # KDF(DH1,DH2,DH3,DH4)
        shared_key = hkdf_extract(salt=None, input_key_material=DH1+DH2+DH3+DH4)
        
        return shared_key
        
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
        
    def send_x3dh_start(self):
        target = input("Enter target username for x3dh: ")
        payload = {"type": "x3dh", 
                    "username": self.username, 
                    "target": target}
        self.ssock.sendall(json.dumps(payload).encode('utf-8'))
    
    def handle_x3dh_initial(self,msg):    
        targets_key_bundle = msg['key_bundle']
        target = msg['target']
        print(f"Got {target} key bundle: {targets_key_bundle}")
        targets_key_bundle = json.loads(targets_key_bundle)
        self.key_bundles[target] = targets_key_bundle
        if self.verify_key_bundle(targets_key_bundle):
            shared_key, ek, EPK = self.compute_shared_x3dh_key_inital(target)
            self.x3dh_sessions_keys[target] = shared_key
            print(shared_key, self.IPK.to_pem()+bytes.fromhex(targets_key_bundle['IPK']))
            iv, cipher, tag = aes_gcm_encrypt(shared_key, f"Hello {target}", self.IPK.to_pem()+bytes.fromhex(self.key_bundles[target]['IPK']))
            msg = {"iv": iv.hex(), "cipher": cipher.hex(), "tag": tag.hex()}
            msg = json.dumps(msg)
            x3dh_link = {
                "IPK_A": self.IPK.to_pem().hex(),
                "EPK_A": EPK.to_pem().hex(),
                "OPK_A": self.OPK.to_pem().hex(),
                "msg": msg,
                "username": self.username,
                "target": target
            }
            x3dh_link = json.dumps(x3dh_link)
            payload = {"type": "x3dh_reaction", 
                        "username": self.username, 
                        "target": target,
                        "x3dh_link": x3dh_link}
            payload = json.dumps(payload)
            self.ssock.sendall(payload.encode('utf-8'))
    
    def handle_x3dh_reaction(self,res):
        print(self.username)
        x3dh_link = json.loads(res['x3dh_link'])
        IPK_A = VerifyingKey.from_pem(bytes.fromhex(x3dh_link['IPK_A']))
        EPK_A = VerifyingKey.from_pem(bytes.fromhex(x3dh_link['EPK_A']))
        OPK_A = VerifyingKey.from_pem(bytes.fromhex(x3dh_link['OPK_A']))
        msg = json.loads(x3dh_link['msg'])
        iv = bytes.fromhex(msg['iv'])
        cipher = bytes.fromhex(msg['cipher'])
        tag = bytes.fromhex(msg['tag'])
        shared_key = self.compute_shared_x3dh_key_reaction(IPK_A,EPK_A)
        
        ad = IPK_A.to_pem()+self.IPK.to_pem()
        print(shared_key, ad)
        plaintext = aes_gcm_decrypt(shared_key, iv, cipher, ad, tag)   
         
        if plaintext == f"Hello {self.username}":
            print(f"X3DH Protocol with {res['username']} completed successfully")
        else:
            print(f"X3DH Protocol with {res['username']} failed")

    def key_bundle_fetch(self, key_bundle):
        print(f"Key bundle fetched: {key_bundle}")
        self.key_bundles = key_bundle
        
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
                    elif message == "register_depricated":
                        self.register()
                    elif message == "x3dh":
                        self.send_x3dh_start()                       
                    else:
                        payload = {"type": "message", "username": self.username, "message": message}
                        message = json.dumps(payload)
                        self.ssock.sendall(message.encode('utf-8'))
                except Exception as e:
                    import traceback
                    traceback.print_exc()
                    print(f"Error sending message: {e}")
                    break
    def handle_messages(self):
        while True:
            try:
                message = self.ssock.recv(1024*8).decode('utf-8')
                if not message:
                    break
                message = json.loads(message)
                type = message['type']
                
                if type == "message":
                    print(f"Message from {message['username']}: {message['message']}")
                
                if type == "server_message":
                    print(f"Server message: {message['message']}")
                
                if type == "x3dh":
                    self.handle_x3dh_initial(message)  
                      
                if type == "x3dh_reaction":
                    self.handle_x3dh_reaction(message)
                    
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"Error handling message: {e}")
                break
if __name__ == "__main__":
    X3DHClient()