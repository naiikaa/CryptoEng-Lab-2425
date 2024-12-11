import socket
import ssl
import threading
import hashlib
import os
import json
class Server:
    def __init__(self):
        self.server_address = ('localhost', 1717)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certfile='server.crt', keyfile='server.key')
        self.sock = self.context.wrap_socket(socket.socket(socket.AF_INET), server_side=True)
        self.sock.bind(self.server_address)
        self.sock.listen(5)
        print(f"Server listening on {self.server_address}")
        self.client_threads = []

    def start(self):
        while True:
            client_socket, client_address = self.sock.accept()
            print(f"Connection from {client_address}")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()
            self.client_threads.append(client_thread)

    def handle_login(self, client_socket,msg):
        username = msg['username']
        with open("database.txt","r") as db:
            for line in db:
                stored_username, salt, salted_hashed_password = line.strip().split(":")
                if stored_username == username:
                    client_socket.sendall(b"Your salt is: " + salt.encode('utf-8'))
                    check_pw = client_socket.recv(2048).decode('utf-8')
                    print(f"Client sent me this hashed password: {check_pw}\n")
                    if check_pw == salted_hashed_password:
                        client_socket.sendall(b"Login successful")
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
        with open('database.txt', 'a') as db:
            db.write(f"{username}:{salt}:{salted_hashed_password}\n")

if __name__ == "__main__":
    server = Server()
    server.start()