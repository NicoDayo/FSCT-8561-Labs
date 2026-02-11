import socket
from cases import initial_hello, msg_case
import hashlib
import pyotp

port = 12345

#temp lockout/disconnect constants for rate limiting
pw_attempts = 5
otp_attempts = 5

connection_held = True
server_socket = socket.socket()
server_socket.bind(("127.0.0.1", port)) #127.0.0.1 being loopback or localhost
print(f"socket binded to localhost with port: {port}")

server_socket.listen(2)
print("Server Started.. Listening...")

USER_DB = {
    "Doki":{
        "hash": b'S\xaa\xeac\x91.\xdc\xcbT\xa6\x9d\xd3\x1d\xc2c~\xc1H\xbe\x13\xf8\xad\x13ju\xd2U\xc5\xdc\xfdIG',
        "otp": "XW2N22IL7UKDSM4DM3DJNNRN56VCKVTK"
    }
}

# Edge cases for the chat feature
def chat_function_cases(user_message: str, conn, state: dict) -> bool:
    Hello = state["Hello"] #compiled all the chat handling cases into one function to organize.
    User = state["User"]
    continue_connection = True
    close_connection = False
    
    if Hello != True and not user_message.startswith("HELLO|"):
        conn.send(b"ERROR| Invalid Requirements, must establish connection with HELLO|<user>\n")
        return continue_connection # If initial command isn't HELLO|

    if Hello == True and user_message.startswith("HELLO|"): 
        conn.send(b"Connection already established for this user.")
        return continue_connection # If the server is already greeted

    if "|" not in user_message:
        conn.send(b"ERROR| Invalid Entry (Missing |)\n")
        return continue_connection # For any command that doesn't include the pipe

    if user_message.startswith("|"):
        conn.send(b"ERROR| Invalid Entry (correct usage is command|)\n")
        return continue_connection # For wrong usage of pipe
    
    if user_message.startswith("HELLO|"):
        reply, Hello, User = initial_hello(user_message, Hello, User)
        state["Hello"] = Hello
        state["User"] = User
        conn.send(reply.encode())
        return continue_connection
    
    elif user_message.startswith("MSG|") and Hello == True:
        reply = msg_case(user_message, User)
        conn.send(reply.encode())
        return continue_connection
    
    elif user_message.startswith("EXIT|"):
        conn.sendall(b"OK|Closing connection...\n")
        return close_connection
    
    conn.send(b"ERROR|Unknown command\n")
    return continue_connection

while connection_held:
    conn, address = server_socket.accept()
    print("Connection received from client:", address)

#flags are organized into states
    state = {
        "Hello": False,
        "User": None,
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
                    conn.sendall(b"ERROR|Login for user required. (LOGIN|username|password\n)")
                    continue

                contents = user_message.split("|")
                if len(contents) != 3:
                    conn.send(b"ERROR|Invalid format, -> LOGIN|username|password\n")
                    continue
                cmd, uname, pwd, = [c.strip() for c in contents]

                if uname not in USER_DB:
                    conn.send(b"ERROR|Unknown user\n")
                    break
                
                #hashing the password that the user typed------
                typed_pw = hashlib.sha256(pwd.encode("utf-8")).digest()
                
                if typed_pw == USER_DB[uname]["hash"]:
                    state["Login_confirm"] = True
                    state["Login_User"] = uname
                    state["pw_attempts"] = 0
                    conn.send(b"OK|Login Successful - OTP AUTH required (6 Digit Code)\n")
                    continue
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
                else:
                    state["otp_attempts"] += 1
                    attempts_remain = otp_attempts - state["otp_attempts"]
                    if attempts_remain <= 0:
                        conn.sendall(b"ERROR|Rate Limited due to failed OTP attempts. Disconnecting..\n")
                        break
                    conn.send(f"ERROR|Invalid or Expired OTP (attempts left: {attempts_remain})\n".encode())
                continue

            continue_conn = chat_function_cases(user_message, conn, state)
            if not continue_conn:
                break

    conn.close()
    print(f"Client:{address} - Disconnected from Server\n")