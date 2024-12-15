import socket
import threading
import json
from utils import *

SOCKET_PORT = 1700
clients = {}
nonce_s = os.urandom(64)
secret_key, public_key = generate_ecdh_key_pair() # intial key pair
sk_ca , pk_ca = generate_server_ca_keys() # certificate authority key pair
sign_sk, sign_pk = generate_server_ca_keys() # signature key pair
sign_ca = ecdsa_sign(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo), sk_ca) # signature of public key
cert = {"public_key": public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(), "signature": decode_correctly(sign_ca)} # certificate
cert = json.dumps(cert)

def tls_response_1(client_socket, X, nonce_c):
    
    k_1_c, k_1_s = keySchedule1(secret_key.exchange(ec.ECDH(), X))
    payload = {"target": "new_client",
               "nonce": decode_correctly(nonce_s),
               "msg": public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
               "source": "server",
               "type": "tls-1"
    }
    msg = json.dumps(payload)
    client_socket.send(msg.encode('utf-8'))
    return k_1_c, k_1_s
    
def tls_response_2(client_socket, X, nonce_c,k_1_c,k_1_s):
    sign = serverSignature(sign_sk,nonce_c,X.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),nonce_s,public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),cert)
    k_2_c, k_2_s = keySchedule2(nonce_c,X.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),nonce_s,public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),secret_key.exchange(ec.ECDH(), X))
    mac_s = serverMac(k_2_s,nonce_c,X.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),nonce_s,public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),sign,sign_ca)
    k_3_c, k_3_s = keySchedule3(nonce_c,X.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),nonce_s,public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),secret_key.exchange(ec.ECDH(), X),sign,cert,mac_s)
    combinded = json.dumps({"cert":cert, "sign":decode_correctly(sign), "mac":decode_correctly(mac_s)})
    iv, cipher, tag = aes_gcm_encrypt(k_1_s, combinded,public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
    payload = {"target": "new_client",
               "nonce": decode_correctly(nonce_s),
               "msg": {"iv":decode_correctly(iv), "cipher":decode_correctly(cipher), "tag":decode_correctly(tag)},
               "source": "server",
               "type": "tls-2"
    }
    msg = json.dumps(payload)
    print(msg)
    client_socket.send(msg.encode('utf-8'))
    return k_2_c, k_2_s, k_3_c, k_3_s
    
def handle_client(client_socket, client_address):
    while True:
        try:
            message = client_socket.recv(1024*8)

            if not message:
                break
            data = from_json(message)
            target_client = data['target']
            msg = data['msg']
            source_client = data['source']
            msg_type = data['type']
            nonce = data['nonce']
            
            if source_client not in clients.keys():
                clients[source_client] = client_socket
            print(f"Received message: {msg} from {client_address} to {target_client}")
            if target_client == "server":
                if msg_type == "tls-0":
                    print(message)
                    X = serialization.load_pem_public_key(msg.encode('utf-8'))
                    k_1_c, k_1_s= tls_response_1(client_socket, X, nonce)
                    k_2_c, k_2_s, k_3_c, k_3_s = tls_response_2(client_socket, X,encode_correctly(nonce), k_1_c, k_1_s)
            elif target_client in clients:
                print(f"Sending message to {target_client}")
                clients[target_client].send(f"Message from {client_address}: {msg}".encode('utf-8'))
            else:
                print(f"Client {target_client} not found.")
                client_socket.send(f"Client {target_client} not found.".encode('utf-8'), client_address)
        except Exception as e:
            print(e)
            print(f"Client {client_address} disconnected")
            break
    client_socket.close()
    del clients[client_address]
    print(f"Client {client_address} disconnected")

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', SOCKET_PORT))
    server_socket.listen(5)
    print(f"Server listening on port {SOCKET_PORT}")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Client {client_address} connected")
        clients[client_address] = client_socket
        client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_handler.start()



if __name__ == "__main__":
    start_server()