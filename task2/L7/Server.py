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
        self.db_encryption_key = None
        self.login_attempts = dict()
        
        if not os.path.exists('db_ecryption_keys.txt'):
            with open('db_ecryption_keys.txt', 'w') as dbek:
                self.db_encryption_key = os.urandom(32).hex()
                dbek.write(self.db_encryption_key)
        else:
            with open('db_ecryption_keys.txt', 'r') as dbek:
                self.db_encryption_key = dbek.read()
        
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
            client_socket.sendall(b"Too many login attempts. Account locked.")
            
        with open("database.txt","r") as db:
            for line in db:
                iv, cipher, tag = line.strip().split(":")
                iv = bytes.fromhex(iv)
                cipher = bytes.fromhex(cipher)
                tag = bytes.fromhex(tag)
                msg = aes_gcm_decrypt(bytes.fromhex(self.db_encryption_key), iv, cipher, b"", tag)
                stored_username, salt, salted_hashed_password = msg.split(":")
                
                if stored_username == username:
                    client_socket.sendall(salt.encode('utf-8'))
                    check_pw = client_socket.recv(2048).decode('utf-8')
                    print(f"Client sent me this hashed password: {check_pw}\n")
                    if check_pw == salted_hashed_password:
                        client_socket.sendall(b"Login successful")
                        break
                        print(f"{username}, Login successful!\n")
                    else:
                        client_socket.sendall(b"Login failed")
                        if username in self.login_attempts:
                            self.login_attempts[username] += 1
                        else:
                            self.login_attempts[username] = 1
                        break
            
            client_socket.sendall(b"User not found. Register first!")
    def user_already_exists(self,username,db):
        if db:
            for line in db:
                stored_username, _, _ = line.split(":")
                if stored_username == username:
                    return True
        return False
    

    def handle_register(self, client_socket,msg):
        username = msg['username']
        password = msg['password']
        with open("database.txt","r") as db:
            if self.user_already_exists(username,db):
                client_socket.sendall(b"User already exists")
            else:
                salt, salted_hashed_password = self.hash_password(password)
                self.store_credentials(username,salt, salted_hashed_password)
                client_socket.sendall(b"Registration successful")
    
    def handle_client(self, client_socket):
        try:
            msg = client_socket.recv(2048).decode('utf-8')
            msg = json.loads(msg)
            type = msg['type']

            if type == "login":
                self.handle_login(client_socket,msg)
            if type == "register":
                self.handle_register(client_socket,msg)
            
        except Exception as e:
            print(f"Error handling client: {e}")
        finally:
            client_socket.close()

    def hash_password(self, password):
        salt = os.urandom(16)
        salted_password = salt + password.encode('utf-8')
        hashed_password = hashlib.sha256(salted_password).hexdigest()
        return salt, salt.hex() + hashed_password

    def store_credentials(self, username,salt, salted_hashed_password):
        msg = f"{username}:{salt}:{salted_hashed_password}"
        iv, cipher, tag = aes_gcm_encrypt(bytes.fromhex(self.db_encryption_key), msg, b"")
        with open('database.txt', 'a') as db:
            db.write(f"{iv.hex()}:{cipher.hex()}:{tag.hex()}\n")

if __name__ == "__main__":
    server = Server()
    server.start()