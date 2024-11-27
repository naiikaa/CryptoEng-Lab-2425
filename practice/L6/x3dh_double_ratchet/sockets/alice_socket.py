import socket
import threading
import json
import time

SERVER_PORT = 1700
IDENTITY = "Alice"
OWN_PORT = 1717

def listen_for_messages(sock):
    while True:
        message, addr = sock.recvfrom(1024)
        print(f"Received message: {message.decode()} from {addr}")

def main():
    # Try connecting to the server
    print(f"{IDENTITY}: Try connecting to SERVER...")
    conn_to_peer = None
    while conn_to_peer is None:
        try:
            conn_to_peer = socket.create_connection(('localhost', SERVER_PORT),source_address=('localhost', OWN_PORT))
        except ConnectionRefusedError:
            print(f"{IDENTITY}: Waiting for SERVER to be online...")
            time.sleep(2)

    # Start a thread to listen for incoming messages
    listener_thread = threading.Thread(target=listen_for_messages, args=(conn_to_peer,))
    listener_thread.daemon = True
    listener_thread.start()


    # Send messages
    while True:
        message = input("Enter message to send: ")
        if message.lower() == 'exit':
            break
        target = input("Enter target client: ")
        payload = {
            "target": target,
            "msg": message,
            "source": IDENTITY
        }
        msg = json.dumps(payload)
        server_address = ('localhost', SERVER_PORT)
        conn_to_peer.sendto(msg.encode(), server_address)

if __name__ == "__main__":
    main()