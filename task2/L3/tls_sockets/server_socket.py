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

cert = {"public_key": public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(), "signature": sign_ca.hex(), "public_key_certificate": pk_ca.to_pem().hex() } # certificate
cert = json.dumps(cert)
assert ecdsa_verify(sign_ca,public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo), pk_ca) # verify signature
tls_keys = dict()

def tls_response_1(client_socket, X, nonce_c):
    
    k_1_cc, k_1_ss = keySchedule1(secret_key.exchange(ec.ECDH(), X))
    payload = {"target": "new_client",
               "nonce": nonce_s.hex(),
               "msg": public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),
               "source": "server",
               "type": "tls-1"
    }
    msg = json.dumps(payload)
    client_socket.send(msg.encode('utf-8'))
    tls_keys["k_1_c"] = k_1_cc
    tls_keys["k_1_s"] = k_1_ss
        
def tls_response_2(client_socket, X, nonce_c):
    sign = serverSignature(sign_sk,nonce_c,X.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),nonce_s,public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),cert)
    k_2_c, k_2_s = keySchedule2(nonce_c,X.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),nonce_s,public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode(),secret_key.exchange(ec.ECDH(), X))
    mac_s = serverMac(k_2_s,nonce_c,X.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),nonce_s,public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),sign,sign_ca)
    k_3_c, k_3_s = keySchedule3(nonce_c,X.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),nonce_s,public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),secret_key.exchange(ec.ECDH(), X),sign,encode_correctly(cert),mac_s)
    tls_keys["sign"] = sign 
    tls_keys["mac_s"] = mac_s
    combinded = json.dumps({"cert":cert, "sign":sign.hex(), "mac":mac_s.hex(), "pk_sign":sign_pk.to_pem().hex()})
    print(tls_keys["k_1_s"])
    iv, cipher, tag = aes_gcm_encrypt(tls_keys["k_1_s"], combinded,public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))
  
    payload = {"target": "new_client",
               "nonce": nonce_s.hex(),
               "msg": {"iv":iv.hex(), "cipher":cipher.hex(), "tag":tag.hex()},
               "source": "server",
               "type": "tls-2"
    }
    msg = json.dumps(payload)
    print(msg+"\n")
    client_socket.send(msg.encode('utf-8'))
    tls_keys["k_2_c"] = k_2_c
    tls_keys["k_2_s"] = k_2_s
    tls_keys["k_3_s"] = k_3_s
    tls_keys["k_3_c"] = k_3_c
    
    
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
            print(f"Received message: {msg} from {client_address} to {target_client}\n")
            if target_client == "server":
                if msg_type == "tls-0":
                    print(message)
                    X = serialization.load_pem_public_key(msg.encode('utf-8'))
                    tls_response_1(client_socket, X, nonce)
                    tls_response_2(client_socket, X,bytes.fromhex(nonce))
                if msg_type == "tls-3":
                    msg = json.loads(msg)
                    mac_c = aes_gcm_decrypt(tls_keys["k_1_c"], bytes.fromhex(msg['iv']),bytes.fromhex(msg['cipher']), X.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),bytes.fromhex(msg['tag']))
                    print(f"Decrypted mac: {mac_c}")
                    mac_c = bytes.fromhex(mac_c)
                    assert mac_c == clientMac(tls_keys["k_2_c"],bytes.fromhex(nonce),X.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),nonce_s,public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo),tls_keys['sign'],sign_ca)
                    print(f"Client {client_address} authenticated\n")
                    client_socket.sendall("Authenticated".encode('utf-8'))
            elif target_client in clients:
                print(f"Sending message to {target_client}\n")
                clients[target_client].send(f"Message from {client_address}: {msg}".encode('utf-8'))
            else:
                print(f"Client {target_client} not found.\n")
                client_socket.sendall(f"Client {target_client} not found.".encode('utf-8'))
        except Exception as e:
            #print stack trace with line number
            import traceback
            traceback.print_exc()
            print(f"Error: {e}\n")
            print(f"Client {client_address} disconnected\n")
            break
    client_socket.close()
    del clients[client_address]
    print(f"Client {client_address} disconnected\n")

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', SOCKET_PORT))
    server_socket.listen(5)
    print(f"Server listening on port {SOCKET_PORT}\n")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Client {client_address} connected\n")
        clients[client_address] = client_socket
        client_handler = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_handler.start()



if __name__ == "__main__":
    start_server()