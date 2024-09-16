
def success(msg):
    print(f"\033[32m[+] {msg}\033[0m")

def show(msg):
    print(f"\033[34m[*] {msg}\033[0m")

def warn(msg):
    print(f"\033[33m[*] {msg}\033[0m")

def error(msg):
    print(f"\033[31m[-] {msg}\033[0m")