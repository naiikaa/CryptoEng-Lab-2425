import socket
import threading
import time
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os, hashlib

def generate_ecdh_key_pair():
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    return private_key, public_key

# Configuration
SERVER_PORT = 65436        # My listening port   
MY_HOST = '127.0.0.1'
TARGET_HOST = '127.0.0.1'
# Flag to track if the party is awaiting a response
awaiting_response = False

class ConnectionLostError(Exception):
    """Custom exception to indicate a lost connection."""
    pass





def forward_messages(source_conn, dest_conn, source_identity, dest_identity):
    while True:
        try:
            data = source_conn.recv(1024)
            if not data:
                break
            dest_conn.sendall(data)
            print(f"Server: Forwarded message from {source_identity} to {dest_identity}")
        except:
            break
    source_conn.close()
    dest_conn.close()

def server():
    my_identity = "Server"
    alice_conn = None
    bob_conn = None

    # Create a listening socket
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.bind((MY_HOST, SERVER_PORT))
    listen_sock.listen(2)
    print(f"{my_identity}: Listening on port {SERVER_PORT}...")

    # Accept connections from Alice and Bob
    while True:
        conn, addr = listen_sock.accept()
        print(f"{my_identity}: Connection from {addr}")
        
        # Connect to the incoming connection
        try:
            conn.sendall(b"Connected to the server")
        except Exception as e:
            print(f"{my_identity}: Failed to send connection confirmation. Error: {e}")
            conn.close()
            continue

        # Receive the client's identity
        identity = conn.recv(1024).decode('utf-8').strip()
        print(identity)
        if identity == "Alice":
            alice_conn = conn
            print(f"{my_identity}: Alice connected.")
            
        elif identity == "Bob":
            bob_conn = conn
            print(f"{my_identity}: Bob connected.")
        else:
            print(f"{my_identity}: Unknown client {identity}. Connection closed.")
            conn.close()

        # When both are connected, start forwarding messages
        if alice_conn and bob_conn:
            threading.Thread(target=forward_messages, args=(alice_conn, bob_conn, "Alice", "Bob"), daemon=True).start()
            threading.Thread(target=forward_messages, args=(bob_conn, alice_conn, "Bob", "Alice"), daemon=True).start()
            alice_conn = None
            bob_conn = None

if __name__ == "__main__":
    server()
