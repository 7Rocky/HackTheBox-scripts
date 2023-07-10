#!/usr/bin/env python3

import json

from hashlib import sha1
from pwn import remote, sys
from sage.all import Matrix, QQ

from Crypto.Util.number import bytes_to_long

host, port = sys.argv[1].split(':')

n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
g = 5
pt = b'william;yarmouth;22-11-2021;09:00'

hs, rs, ss, ks_lsb = [], [], [], []

with open('signatures.txt') as f:
    f.readline()
    while (line := f.readline()):
        values = line.split(';')
        hs.append(int(values[0], 16))
        rs.append(int(values[1], 16))
        ss.append(int(values[2], 16))
        ks_lsb.append(int(values[3], 2))

p = n

a_i = list(
    map(
        lambda s, h, k_lsb: pow(2, -7, p) * (pow(s, -1, p) * h - k_lsb) % p,
        ss, hs, ks_lsb
    )
)

t_i = list(
    map(
        lambda r, s: pow(2, -7, p) * pow(s, -1, p) * r % p,
        rs, ss
    )
)

X = 2 ** (n.bit_length() - 7)

raw_matrix = []

for i in range(len(a_i)):
    raw_matrix.append([0] * i + [p] + [0] * (len(a_i) - i + 1))

raw_matrix.append(t_i + [X / p, 0])
raw_matrix.append(a_i + [0, X])

M = Matrix(QQ, raw_matrix)
L = M.LLL()

for row in L.rows():
    k = int(row[0] * 2 ** 7 + ks_lsb[0])

    if rs[0] == pow(g, k, n) and row[-1] == X:
        key = (ss[0] * k - hs[0]) * pow(rs[0], -1, n) % n
        h = sha1(pt).digest()
        h = bytes_to_long(h)
        h = bin(h)[2:]
        h = int(h[:len(bin(n)[2:])], 2)
        r = pow(g, k, n)
        s = (pow(k, -1, n) * (h + key * r)) % n

        io = remote(host, port)
        io.sendlineafter(b'> ', json.dumps({'pt': pt.decode(), 'r': hex(r), 's': hex(s)}).encode())
        io.success(io.recv().decode())
