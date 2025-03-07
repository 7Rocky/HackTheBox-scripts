#!/usr/bin/env python3

import os
import requests
import sys

from base64 import b64encode as b64e, b64decode as b64d
from hashlib import sha256
from secrets import randbelow

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


URL = '127.0.0.1:1337' if len(sys.argv) == 1 else sys.argv[1]

# Step 1
r = requests.post(f'http://{URL}/api/request-session-parameters')

g = int(r.json().get('g'), 16)
p = int(r.json().get('p'), 16)

# Step 2
b = randbelow(p)
client_public_key = pow(g, b, p)

r = requests.post(f'http://{URL}/api/init-session', json={
    'client_public_key': client_public_key
})

server_public_key = int(r.json().get('server_public_key'), 16)

key = pow(server_public_key, b, p)
session_key = sha256(str(key).encode()).digest()

# Step 3
r = requests.post(f'http://{URL}/api/request-challenge')

encrypted_challenge = b64d(r.json().get('encrypted_challenge'))
iv, ct = encrypted_challenge[:16], encrypted_challenge[16:]

cipher = AES.new(session_key, AES.MODE_CBC, iv)
challenge = unpad(cipher.decrypt(ct), 16)

# Step 4
iv = os.urandom(16)
cipher = AES.new(session_key, AES.MODE_CBC, iv)
packet_data = b64e(iv + cipher.encrypt(pad(b'flag', 16))).decode()

r = requests.post(f'http://{URL}/api/dashboard', json={
    'challenge': sha256(challenge).hexdigest(),
    'packet_data': packet_data
})

packet_data = b64d(r.json().get('packet_data'))

iv, ct = packet_data[:16], packet_data[16:]
cipher = AES.new(session_key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(ct), 16).decode()
print(flag)
