import socket
connection_held = True

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost", 12345))
while connection_held:
    user_input = input("Enter a Command (use HELP| for commandlist) > ")
    if user_input.startswith("HELP|"):
        print("""
            Command Usage: COMMAND|<text>
            - HELLO|<user> - communicate with server
            - MSG|<message> - sending a message
            - EXIT| - Exit Connection
                """)
        continue
    if not user_input.strip():
        print("ERROR| Empty value.\n")
        continue
    client.send(user_input.encode())
    server_response = client.recv(1024).decode()
    print(f"(Server) > {server_response}")
    if user_input.strip().startswith("EXIT|"):
        client.close()
        break