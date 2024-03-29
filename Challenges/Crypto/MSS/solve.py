#!/usr/bin/env python3

import json

from hashlib import sha256
from pwn import process, remote, sys

from sympy.ntheory.modular import crt

from Crypto.Cipher import AES
from Crypto.Util.number import getPrime
from Crypto.Util.Padding import unpad


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'server.py'])

    host, port = sys.argv[1].split(':')
    return remote(host, port)


io = get_process()

primes, remainders = [], []

for _ in range(19):
    p = getPrime(15)
    io.sendlineafter(b'query = ', json.dumps(
        {'command': 'get_share', 'x': p}).encode())
    r = json.loads(io.recvline().decode()).get('y')
    primes.append(p)
    remainders.append(r % p)

key = crt(primes, remainders)[0]

io.sendlineafter(b'query = ', json.dumps({'command': 'encrypt_flag'}).encode())
io.recvuntil(b'[+] Here is your encrypted flag : ')
data = json.loads(io.recvuntil(b'}').decode())

iv = bytes.fromhex(data.get('iv'))
enc_flag = bytes.fromhex(data.get('enc_flag'))

key = sha256(str(key).encode()).digest()
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(enc_flag), AES.block_size).decode()
io.success(flag)
