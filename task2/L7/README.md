# Registration and Login Process
## Registration Process
### 1. Client Side:
- The client initiates the registration process by sending a registration request to the server.
- The client constructs a payload with the type "register", username, and password.
- The payload is then sent to the server.

```python
# Client.py
payload = {"type": "register", "username": self.username, "password": self.password}
message = json.dumps(payload)
self.sock.sendall(message.encode('utf-8'))
response = self.sock.recv(4096).decode('utf-8')
print(f"Got response: {response}\n")
```

### 2. Server Side:
- The server receives the registration request and processes it.
- The server checks if the username already exists using the user_already_exists function.
- If the username does not exist, the server hashes the password using the hash_password function.
- The server stores the credentials in the database using the store_credentials function.
- The server sends a response back to the client indicating whether the registration was successful or if the user already exists.
```python
# Server.py
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
```
## Login Process
### 1. Client Side:
- The client initiates the login process by sending a login request to the server.
- The client constructs a payload with the type "login" and username.
- The payload is then sent to the server.
- The client receives the salt from the server and computes the salted password.
- The client hashes the salted password and sends it back to the server.
```python
# Client.py
payload = {"type": "login", "username": self.username}
message = json.dumps(payload)
self.sock.sendall(message.encode('utf-8'))
salt = self.sock.recv(1024).decode('utf-8')
salt = encode_correctly(salt[2:-1])
print(f"Got salt: {salt}\n")
salted_password = salt + self.password.encode('utf-8')
print(f"Salted password: {salted_password}\n")
hashed_password = hashlib.sha256(salted_password).hexdigest()
print(f"Sending salted password: {salt.hex() + hashed_password}\n")
self.sock.sendall((salt.hex() + hashed_password).encode('utf-8'))
response = self.sock.recv(1024).decode('utf-8')
print(f"Got response: {response}\n")
```
### 2. Server Side:
- The server receives the login request and processes it.
- The server retrieves the stored salt and hashed password for the given username from the database.
- The server sends the salt to the client.
- The server receives the hashed password from the client and compares it with the stored hashed password.
- The server sends a response back to the client indicating whether the login was successful or failed.

```python
# Server.py
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
```

## Precautions against offline and online dictonary attacks
### Offline attacks
- the saved `username:salt:salted_hashed_password` database is encrypted
- the encryption key is stored seperatly and is used to encrypt new lines added to the database and decrypt lines while reading
- if an adversary gets the database + list of plaintext passwords he still needs to get the seperate database encryption key so he can get to the salts
- this does not 100% block an offline attack, which is nearly impossible to achieve, but it adds another layer of security 

### Online attacks
- brute forcing passwords is not possible since we have a tracker for attempts and after 3 failed attempts a user account is locked