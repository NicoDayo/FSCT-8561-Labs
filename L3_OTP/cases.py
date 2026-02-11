def initial_hello(user_input: str, hello_check: bool, user: str):
    message = user_input[6:]
    if message.strip() == "":
        return "ERROR| no username specified\n", hello_check, user
    user = message.strip()
    hello_check = True
    return f"OK| greetings {user}! Nice to meet you.\n", hello_check, user

def msg_case(user_input: str, user: str):
    message = user_input[4:]
    if message == "":
        return f"ERROR| empty message\n"
    if len(message) > 120:
        return f"ERROR| Message cannot exceed 120 characters\n"
    print(f"[{user}] > {message}")
    return "OK|Text Sent\n"