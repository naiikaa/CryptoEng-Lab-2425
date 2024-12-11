import socket
import ssl
import threading
import json
import hashlib

class Client:
    def __init__(self):
        self.username = input("Enter your username: ")
        self.password = input("Enter your password: ")
        self.server_address = ('localhost', 1717)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self.context.load_verify_locations('server.crt')
        self.sock = self.context.wrap_socket(socket.socket(socket.AF_INET), server_hostname='localhost')
        self.connect_to_server()

    def connect_to_server(self):
        try:
            self.sock.connect(self.server_address)
            print(f"Connected to server at {self.server_address}")
            self.send_messages()
        except Exception as e:
            print(f"Failed to connect to server: {e}")
            self.sock.close()

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
                        self.sock.sendall(message.encode('utf-8'))
                        response = self.sock.recv(4096).decode('utf-8')
                        print(f"Got response: {response}\n")

                    elif message == "login":
                        payload = {"type": "login", "username": self.username}
                        message = json.dumps(payload)
                        self.sock.sendall(message.encode('utf-8'))
                        salt = self.sock.recv(1024).decode('utf-8')
                        salted_password = salt.encode('utf-8').hex() + self.password
                        hashed_password = hashlib.sha256(salted_password.encode('utf-8')).hexdigest()
                        print(f"Sending salted password: {hashed_password}\n")
                        self.sock.sendall((salt.encode('utf-8').hex()+hashed_password).encode('utf-8'))
                    else:
                        payload = {"type": "message", "username": self.username, "message": message}
                        message = json.dumps(payload)
                        self.sock.sendall(message.encode('utf-8'))
                except Exception as e:
                    print(f"Error sending message: {e}")
                    break

if __name__ == "__main__":
    Client()