import socket, getpass
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
    if server_response.startswith("Login Successful"):
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
    if otp_response.startswith("OTP verification SUCCESS"):
        break
    if "Disconnecting" in otp_response or "Rate Limited" in otp_response:
        client.close()
        raise SystemExit(0)

print("Authenticated..")
client.close() # closed for now just to focus on the authenticaiton functionatly