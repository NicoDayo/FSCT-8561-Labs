import socket, hashlib, pyotp
port = 12345

#temp lockout/disconnect constants for rate limiting
pw_attempts = 5
otp_attempts = 5
server_socket = socket.socket()
server_socket.bind(("127.0.0.1", port)) #127.0.0.1 being loopback or localhost
print(f"socket binded to localhost with port: {port}")
server_socket.listen(2)
print("Server Started.. Listening...")

# User database is used here purely as a test user to test the app and login.
USER_DB = {
    "Doki":{
        "hash": b'S\xaa\xeac\x91.\xdc\xcbT\xa6\x9d\xd3\x1d\xc2c~\xc1H\xbe\x13\xf8\xad\x13ju\xd2U\xc5\xdc\xfdIG',
        "otp": "XW2N22IL7UKDSM4DM3DJNNRN56VCKVTK"
    }
}

while True:
    conn, address = server_socket.accept()
    print("Connection received from client:", address)

# flags are organized into states in order to give me signifying states 
    state = {
        "Login_confirm": False,
        "Login_User": None,
        "OTP_Confirm": False,
        "pw_attempts": 0,
        "otp_attempts": 0
    }

    with conn:
        while True:
            client_data = conn.recv(512)
            if not client_data:
                break

            user_message = client_data.decode().strip()

            #login cases----
            if not state["Login_confirm"]:
                if not user_message.startswith("LOGIN|"):
                    conn.sendall(b"ERROR|Login for user required.\n)")
                    continue

                contents = user_message.split("|")
                if len(contents) != 3:
                    conn.send(b"ERROR|Invalid format\n")
                    continue
                cmd, uname, pwd, = [c.strip() for c in contents]

                if uname not in USER_DB:
                    conn.send(b"ERROR|Unknown user\n")
                    break
                
                # hashing the password that the user typed, hashing prevents any sort of password beign visible and legible as plaintext
                typed_pw = hashlib.sha256(pwd.encode("utf-8")).digest()
                
                if typed_pw == USER_DB[uname]["hash"]:
                    state["Login_confirm"] = True
                    state["Login_User"] = uname
                    state["pw_attempts"] = 0
                    conn.send(b"OK|Login Successful - OTP AUTH required (6 Digit Code)\n")
                else:
                    state["pw_attempts"] += 1
                    attempts_remain = pw_attempts - state["pw_attempts"]
                    if attempts_remain <= 0:
                        conn.sendall(b"ERROR|Rate Limited due to failed pw attempts. Disconnecting..\n")
                        break
                    conn.send(f"ERROR|Login Failed - Invalid password (attempts left: {attempts_remain})\n".encode())
                continue

            # OTP Authentication
            if state["Login_confirm"] and not state["OTP_Confirm"]:
                if not user_message.startswith("OTP|"):
                    conn.send(b"ERROR|OTP required\n")
                    continue #if somehow the command for OTP| does not get appended to the 6 digit code, (mostly debugging log)

                otp_code = user_message[4:].strip()
                uname = state["Login_User"]

                timed_otp = pyotp.TOTP(USER_DB[uname]["otp"])
                
                if timed_otp.verify(otp_code, valid_window=1):
                    state["OTP_Confirm"] = True
                    state["otp_attempts"] = 0
                    conn.send(b"OK|OTP verification SUCCESS, welcome\n")
                    break
                else:
                    state["otp_attempts"] += 1
                    attempts_remain = otp_attempts - state["otp_attempts"]
                    if attempts_remain <= 0:
                        conn.sendall(b"ERROR|Rate Limited due to failed OTP attempts. Disconnecting..\n")
                        break
                    conn.send(f"ERROR|Invalid or Expired OTP (attempts left: {attempts_remain})\n".encode())
                continue
    conn.close()
    print(f"Client:{address} - Disconnected from Server\n")