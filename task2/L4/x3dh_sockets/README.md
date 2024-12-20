# X3DH Protocol

## How to run the protocol

### Running the Server
Open a new terminal and run the [Server.py](/task2/L4/x3dh_sockets/Server.py)

### Running the Clients
1. Open two new terminals and run [Client.py](/task2/L4/x3dh_sockets/Cleint.py) in both terminals
2. Enter two different names and register the users by typing `register`
```zsh
#Terminal 1#
Enter your username: Alice
register
```
```zsh
#Terminal 2#
Enter your username: Bob
register
```
3. In of the terminals start the X3DH protocol by typing `x3dh`
```zsh
#Terminal 1#
x3dh
Enter target username for x3dh: Bob
```
4. Server Output
```zsh
#Terminal 0#
Connection from ('127.0.0.1', 12345)
Registered Alice successfully with keybundle {...}
Connection from ('127.0.0.1', 12346)
Registered Bob successfully with keybundle {...}
Sent keybundle of Bob to Alice
Forwarded x3dh reaction to Bob
```
5. Client 1 Output
```
#Terminal 1#
Got Bob key bundle: {...}
X3DH Protocol with Bob completed successfully
```
1. Client 2 Output
```
#Terminal 2#
X3DH Protocol with Alice completed successfully
```