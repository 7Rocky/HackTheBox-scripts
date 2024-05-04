#!/usr/bin/env python3

import ecc

from hashlib import md5
from math import isqrt
from pwn import process, remote, sys

from sage.all import crt, EllipticCurve, GF, next_prime

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'server.py'])

    host, port = sys.argv[1].split(':')
    return remote(host, port)


io = get_process()

io.recvuntil(b'Encrypted flag: ')
flag_enc = bytes.fromhex(io.recvline().strip().decode())

io.recvuntil(b'IV: ')
iv = bytes.fromhex(io.recvline().strip().decode())

io.recvuntil(b'N: ')
n = int(io.recvline().decode())

io.recvuntil(b'ECRSA Ciphertext: Point(x=')
Ax = int(io.recvuntil(b',')[:-1].decode())
io.recvuntil(b'y=')
Ay = int(io.recvuntil(b')')[:-1].decode())

io.sendlineafter(b'[y/n]> ', b'y')
io.recvuntil(b'Point(x=')
Rx = int(io.recvuntil(b',')[:-1].decode())
io.recvuntil(b'y=')
Ry = int(io.recvuntil(b')')[:-1].decode())

q = isqrt(n)

while n % q != 0:
    q = next_prime(q)

p = n // q
io.info(f'{p = }')
io.info(f'{q = }')

e = next_prime(p >> (n.bit_length() // 4))
io.info(f'{e = }')

a = ((pow(Ay, 2, n) - pow(Ax, 3, n) - pow(Ry, 2, n) + pow(Rx, 3, n)) * pow(Ax - Rx, -1, n)) % n
b = (pow(Ay, 2, n) - pow(Ax, 3, n) - a * Ax) % n
io.info(f'{a = }')
io.info(f'{b = }')

En = ecc.EllipticCurve(a, b, n)
Ep = EllipticCurve(GF(p), [a, b])
Eq = EllipticCurve(GF(q), [a, b])

Ap = Ep(Ax, Ay)
Aq = Eq(Ax, Ay)

Gp = pow(e, -1, Ep.order()) * Ap
Gq = pow(e, -1, Eq.order()) * Aq
Gn_x = crt([int(Gp.x()), int(Gq.x())], [p, q])
assert En.multiply(En.lift_x(Gn_x, p, q), e) == ecc.Point(Ax, Ay)
io.success(f'{Gn_x = }')

key = md5(str(Gn_x).encode()).digest()
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = unpad(cipher.decrypt(flag_enc), AES.block_size).decode()
io.success(flag)
