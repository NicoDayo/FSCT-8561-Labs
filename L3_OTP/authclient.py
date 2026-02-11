import socket
import getpass
connection_held = True

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost", 12345))

# Password login
username = input("Username: ").strip()
while True:
    password = getpass.getpass("Password (input hidden): ")
    client.sendall(f"LOGIN|{username}|{password}\n".encode())

    server_response = client.recv(1024).decode(errors="replace")
    if not server_response:
        print("(Server) disconnected.")
        client.close()
        raise SystemExit(0)

    print(f"(Server) > {server_response}")

    if server_response.startswith("OK|"):
        break

    if "Disconnecting" in server_response or "Rate Limited" in server_response:
        client.close()
        raise SystemExit(0)

# OTP check
while True:
    otp = input("Enter 6 digit OTP: ").strip()
    client.sendall(f"OTP|{otp}\n".encode())

    otp_response = client.recv(1024).decode(errors="replace")
    if not otp_response:
        print("(Server) disconnected.")
        client.close()
        raise SystemExit(0)

    print(f"(Server) > {otp_response}")

    if otp_response.startswith("OK|"):
        break

    if "Disconnecting" in otp_response or "Rate Limited" in otp_response:
        client.close()
        raise SystemExit(0)
    
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
    client.sendall((user_input.strip() + "\n").encode())
    server_response = client.recv(1024).decode()
    print(f"(Server) > {server_response}")
    if user_input.strip().startswith("EXIT|"):
        client.close()
        break