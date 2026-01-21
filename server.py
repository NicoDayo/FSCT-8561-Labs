import socket
from cases import initial_hello, msg_case

port = 12345
connection_held = True
server_socket = socket.socket()
server_socket.bind(("127.0.0.1", port)) #127.0.0.1 being loopback or localhost
print(f"socket binded to localhost with port: {port}")

server_socket.listen(2)
print("Server Started.. Listening...")

while connection_held:
    conn, address = server_socket.accept()
    print("Connection received from client:", address)

    # flags
    Hello = False
    User = None

    while True:
        client_data = conn.recv(512)
        user_message = client_data.decode().strip()

        # These validate the command sent by the client as well as processing valid commands

        if Hello != True and not user_message.startswith("HELLO|"):
            conn.send(b"ERROR| Invalid Requirements, must establish connection with HELLO|<user>\n")
            continue # If initial command isn't HELLO|

        if Hello == True and user_message.startswith("HELLO|"): 
            conn.send(b"Connection already established for this user.")
            continue # If the server is already greeted

        if "|" not in user_message:
            conn.send(b"ERROR| Invalid Entry (Missing |)\n")
            continue # For any command that doesn't include the pipe

        if user_message.startswith("|"):
            conn.send(b"ERROR| Invalid Entry (correct usage is command|)\n")
            continue # For wrong usage of pipe

        if user_message.startswith("HELLO|"):
            reply, Hello, User = initial_hello(user_message, Hello, User)
        elif user_message.startswith("MSG|") and Hello == True:
            reply = msg_case(user_message, User)
        elif user_message.startswith("EXIT|"):
            conn.sendall(b"OK|Closing connection...\n")
            connection_held = False
            break
        conn.sendall(reply.encode())
    conn.close()
    print(f"Client:{address} - Disconnected from Server\n")