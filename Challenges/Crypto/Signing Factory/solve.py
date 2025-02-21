#!/usr/bin/env python3

from ast import literal_eval
from math import prod
from pwn import b64d, b64e, process, re, remote, sys

from sympy.ntheory import factorint

from Crypto.Util.number import long_to_bytes


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'server.py'])

    host, port = sys.argv[1].split(':')
    return remote(host, port)


golden_ratio = 2654435761

io = get_process()

io.sendlineafter(b'[+] Option >> ', b'2')
io.recvuntil(b'following equations:')
io.recvline()
eqs = literal_eval(io.recvline().decode())

rnds = [int(re.findall(fr'equation\(unknown, (\d+), {golden_ratio}\)', eq)[0]) for eq in eqs]
ress = [int(eq.split(' = ')[1]) for eq in eqs]

hash_n = prod(res * pow(rnd, -1, golden_ratio) % golden_ratio for res, rnd in zip(ress, rnds))
io.sendlineafter(b'Enter the hash(N): ', str(hash_n).encode())

io.recvuntil(b'(e,N) = ')
e, n = literal_eval(io.recvline().decode())

hash_var = lambda key: ((key % golden_ratio) * golden_ratio) >> 32

admin = int(b'System_Administrator'.hex(), 16)
hash_admin = hash_var(admin)

tokens = []

for factor, exponent in factorint(hash_admin).items():
    k = 0
    target = ((factor ** exponent) << 32) // golden_ratio + 1

    while re.search(b'[^a-zA-Z0-9]', long_to_bytes((target % golden_ratio) + k * golden_ratio)):
        k += 1

    username = long_to_bytes((target % golden_ratio) + k * golden_ratio)
    io.sendlineafter(b'[+] Option >> ', b'0')
    io.sendlineafter(b'Enter a username: ', username)
    io.recvuntil(b'Your session token is ')
    tokens.append(int(b64d(literal_eval(io.recvline().decode())).decode()))

io.sendlineafter(b'[+] Option >> ', b'1')
io.sendlineafter(b'Enter your username: ', b'System_Administrator')
io.sendlineafter(b'Enter your authentication token: ', b64e(str(prod(tokens) % n).encode()).encode())

io.recvuntil(b'[+] Welcome back admin! The note you left behind from your previous session was: ')
io.success(io.recvline().decode())
