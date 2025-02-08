import socket
import ssl
import threading
import json
import hashlib
from utils import *
import time
import utils 

class Client:
    def __init__(self):
        self.username = input("Enter your username: ")
        self.password = input("Enter your password: ")
        self.server_address = ('localhost', 7777)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_verify_locations('./task3/L9/server.crt')
        self.ssock = None
        self.sock = None
        self.sk , self.pk = generate_server_ca_keys()
        self.rw = None
        self.rw_key = None
        self.key_info = {}
        self.last_alpha = None

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
            #sending thread
            self.send_thread = threading.Thread(target=self.send_messages)
            self.send_thread.start()
            #listening thread
            self.listen_thread = threading.Thread(target=self.handle_messages)
            self.listen_thread.start()    

            self.init_opqaue()
        except Exception as e:
            print(f"Failed to connect to server: {e}")
            self.ssock.close()

    def init_opqaue(self):
        print("Initiating OPRF registration...")
        payload = {"type": "register", "username": self.username, "password": self.password}
        message = json.dumps(payload)
        self.ssock.sendall(message.encode('utf-8'))

    def init_login(self):
        print("Initiating OPRF login...")
        self.last_alpha = int.from_bytes(os.urandom(32),'big') % utils.n
        h_pw_alpha = (hash_to_curve(self.password.encode())*self.last_alpha).to_bytes()
        payload = {"type": "login", "username": self.username, "h(pw)_alpha": h_pw_alpha.hex()}
        message = json.dumps(payload)
        self.ssock.sendall(message.encode('utf-8'))
        print(f"Sent login request with payload: {payload}")

    def handle_login_reaction(self,message):
        h_pw_alpha_salt = message['h(pw)_alpha_salt']
        enc_client_key_info = json.loads(message['enc_client_key_info'])
        h_pw_salt = h_pw_alpha_salt * inverse(self.last_alpha)
        self.rw = hasher(self.password.encode() + h_pw_salt.to_bytes()).digest()
        self.rw_key = hkdf_extract(None, self.rw)
        self.key_info = aes_gcm_decrypt(self.rw_key, enc_client_key_info['iv'], enc_client_key_info['ciphertext'],b"", enc_client_key_info['tag'])
        print(f"Key info: {self.key_info}")


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

                    if message['message'] == "User registered successfully. Try logging in.":
                        self.init_login()
                        
                    if message['message'] == "User already exists. Try logging in.":
                        self.init_login()
                    
                if type == "login_reaction":
                    self.handle_login_reaction(message)
                    
            except Exception as e:
                import traceback
                traceback.print_exc()
                print(f"Error handling message: {e}")
                break

    def send_messages(self):
        while True:
            message = input("Enter message: ")
            if message:
                try:
                    if message == "exit":
                        self.sock.close()
                        break
                    else:
                        payload = {"type": "message", "username": self.username, "message": message}
                        message = json.dumps(payload)
                        self.ssock.sendall(message.encode('utf-8'))
                except Exception as e:
                    print(f"Error sending message: {e}")
                    break

if __name__ == "__main__":
    Client()