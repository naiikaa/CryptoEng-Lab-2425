import socket
import ssl
import threading
import json
import hashlib
from utils import encode_correctly
class Client:
    def __init__(self):
        self.username = input("Enter your username: ")
        self.password = input("Enter your password: ")
        self.server_address = ('localhost', 1717)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_verify_locations('server.crt')
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ssock = self.context.wrap_socket(self.sock, server_hostname='localhost')

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

    def send_messages(self):
        while True:
            message = input("Enter message: ")
            if message:
                try:
                    if message == "exit":
                        self.sock.close()
                        break
                    elif message == "register":
                        payload = {"type": "register", "username": self.username, "password": self.password}
                        message = json.dumps(payload)
                        self.ssock.sendall(message.encode('utf-8'))
                        response = self.ssock.recv(4096).decode('utf-8')
                        print(f"Got response: {response}\n")

                    elif message == "login":
                        payload = {"type": "login", "username": self.username}
                        message = json.dumps(payload)
                        self.ssock.sendall(message.encode('utf-8'))
                        salt = self.ssock.recv(1024).decode('utf-8')
                        salt = encode_correctly(salt[2:-1])
                        print(f"Got salt: {salt}\n")
                        salted_password =  salt + self.password.encode('utf-8')
                        print(f"Salted password: {salted_password}\n")
                        hashed_password = hashlib.sha256(salted_password).hexdigest()
                        print(f"Sending salted password: {salt.hex()+hashed_password}\n")
                        self.ssock.sendall((salt.hex()+hashed_password).encode('utf-8'))
                        response = self.ssock.recv(1024).decode('utf-8')
                        print(f"Got response: {response}\n")
                    else:
                        payload = {"type": "message", "username": self.username, "message": message}
                        message = json.dumps(payload)
                        self.ssock.sendall(message.encode('utf-8'))
                except Exception as e:
                    print(f"Error sending message: {e}")
                    break

if __name__ == "__main__":
    Client()