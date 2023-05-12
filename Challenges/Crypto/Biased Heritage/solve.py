#!/usr/bin/env python3

from Crypto.Util.number import bytes_to_long, long_to_bytes
from hashlib import sha256
from pwn import process, remote, sys
from sage.all import matrix, QQ


p = 0x184e26a581fca2893b2096528eb6103ac03f60b023e1284ebda3ab24ad9a9fe0e37b33eeecc4b3c3b9e50832fd856e9889f6c9a10cde54ee798a7c383d0d8d2c3
g = 3
q = (p - 1) // 2


def H(msg):
    return bytes_to_long(2 * sha256(msg).digest()) % q


def sign(msg, x):
    k = H(msg + long_to_bytes(x))
    r = pow(g, k, p) % q
    e = H(long_to_bytes(r) + msg)
    s = (k - x * e) % q
    return (s, e)


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'server.py'])

    host, port = sys.argv[1].split(':')
    return remote(host, port)


io = get_process()

io.sendlineafter(b'> ', b'S')
io.sendlineafter(b'Enter message> ', b'A'.hex().encode())
io.recvuntil(b'Signature: ')
s1, e1 = eval(io.recvline().decode())

io.sendlineafter(b'> ', b'S')
io.sendlineafter(b'Enter message> ', b'B'.hex().encode())
io.recvuntil(b'Signature: ')
s2, e2 = eval(io.recvline().decode())

R = 2 ** 256
M = pow(R + 1, -1, q)

a1 = -M * s1 % q
a2 = -M * s2 % q
t1 = M * e1 % q
t2 = M * e2 % q

M = matrix(QQ, [
    [q,  0,  0,     0],
    [0,  q,  0,     0],
    [t1, t2, R / q, 0],
    [a1, a2, 0,     R],
])

B = M.LLL()

for row in B.rows():
    k1, k2 = -row[0], -row[1]

    x1 = ((R + 1) * k1 - s1) * pow(e1, -1, q) % q
    x2 = ((R + 1) * k2 - s2) * pow(e2, -1, q) % q

    if (s1, e1) == sign(b'A', x1):
        x = x1
    elif (s2, e2) == sign(b'B', x2):
        x = x2
    else:
        continue

    s, e = sign(b'right hand', x)

    io.sendlineafter(b'> ', b'V')
    io.sendlineafter(b'Enter message> ', b'right hand'.hex().encode())
    io.sendlineafter(b'Enter s> ', str(s).encode())
    io.sendlineafter(b'Enter e> ', str(e).encode())

    io.success(io.recv().decode())
    break
