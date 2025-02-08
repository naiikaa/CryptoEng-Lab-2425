import socket
import ssl
import threading
import hashlib
import os
import json
from utils import *
import utils

class Server:
    def __init__(self):
        self.server_address = ('localhost', 7777)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile='./task3/L9/server.crt', keyfile='./task3/L9/server.key')
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(self.server_address)
        self.sock.listen(5)
        self.ssock = self.context.wrap_socket(self.sock, server_side=True)
        print(f"Server listening on {self.server_address}")
        self.client_threads = []
        self.db_encryption_key = None
        self.login_attempts = dict()
        self.sk , self.PK = generate_server_ca_keys()
        self.database_path = "./task3/L9/database.txt"
        #check if database exists and create if not
        if not os.path.exists(self.database_path):
            with open(self.database_path,"w") as db:
                pass
        
    def start(self):
        while True:
            client_socket, client_address = self.ssock.accept()
            print(f"Connection from {client_address}")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()
            self.client_threads.append(client_thread)

    def handle_login(self, client_socket,msg):
        username = msg['username']
        if username in self.login_attempts and self.login_attempts[username] >= 3:
            self.send_server_message(client_socket,"Too many login attempts. Try again later.")            
        
        with open(self.database_path,"r") as db:
            for line in db:
                if line['username'] == username:
                    h_pw_alpha = msg['h(pw)_alpha']
                    h_pw_alpha_s = h_pw_alpha * line['salt']
                    h_pw_alpha_salt = h_pw_alpha_s.to_bytes()
                    enc_client_key_info = line['enc_client_key_info']
                    payload = {"type": "login_reaction", "h(pw)_alpha_salt": h_pw_alpha_salt, "enc_client_key_info": enc_client_key_info}
                    client_socket.sendall(json.dumps(payload).encode('utf-8'))
                    break
            
            
            client_socket.sendall(b"User not found. Register first!")
    
    def user_already_exists(self,username,db):
        if db:
            for line in db:
                dump = json.loads(line)
                stored_username = dump['username']
                if  stored_username == username:
                    return True
        return False
    def send_server_message(self,client_socket,message):
        client_socket.sendall(json.dumps({"type":"server_message","message":message}).encode('utf-8'))

    def register_user(self, client_socket,msg):
        username = msg['username']
        password = msg['password']
        salt = int.from_bytes(os.urandom(32),'big') % utils.n
        rw = hasher(password.encode() + (hash_to_curve(password.encode())*salt).to_bytes()).digest()  
        rw_key = hkdf_extract(salt=None, input_key_material=rw)
        lskc, lPKc = generate_server_ca_keys()
        lsks, lPKs = generate_server_ca_keys()
        client_key_info = {"lskc":lskc.to_pem().hex(), "lPKc":lPKc.to_pem().hex(), "lPKs":lPKs.to_pem().hex()}    
        server_key_info = {"lPKc":lPKc.to_pem().hex(), "lPKs":lPKs.to_pem().hex(), "lsks":lsks.to_pem().hex()}
        iv,cipher,tag = aes_gcm_encrypt(rw_key, json.dumps(client_key_info), b"")
        
        with open(self.database_path,"a") as db:
            writable_json = json.dumps({"username":username, "salt":salt, "server_key_info":server_key_info, "enc_client_key_info": {"iv":iv.hex(), "cipher":cipher.hex(), "tag":tag.hex()}})
            db.write(writable_json+"\n")
    
    def handle_register(self, client_socket,msg):
        username = msg['username']
        with open(self.database_path,"r") as db:
            if self.user_already_exists(username,db):
                self.send_server_message(client_socket,"User already exists. Try logging in.")
            else:
                self.register_user(client_socket,msg)
                self.send_server_message(client_socket,"User registered successfully. Try logging in.")
        print(f"Registered user {username}") 

    def handle_client(self, client_socket):
        try:
            msg = client_socket.recv(4096).decode('utf-8')
            msg = json.loads(msg)
            print(f"Received message: {msg}")
            type = msg['type']

            if type == "login":
                print(f"Login attempt from {msg['username']} with h(pw)_alpha: {msg['h(pw)_alpha']}")
                self.handle_login(client_socket,msg)
            if type == "register":
                print(f"Register attempt from {msg['username']} with password: {msg['password']}")
                self.handle_register(client_socket,msg)
            if type == "message":
                print(f"Message from {msg['username']}: {msg['message']}")
            
        except Exception as e:
            print(f"Error handling client: {e.with_traceback()}")
            print(f"msg: {msg}")
        finally:
            client_socket.close()

if __name__ == "__main__":
    server = Server()
    server.start()