#!/usr/bin/env python3

import json

from hashlib import sha1

from pwn import remote, sys
from ecdsa.ecdsa import generator_256

from sage.all import Matrix, ZZ


host, port = sys.argv[1].split(':')
io = remote(host, port)

io.sendlineafter(
    b'Options:\n1.List files\n2.Access a file\n',
    json.dumps({'option': 'list'}).encode()
)

files = json.loads(io.recvline().decode())['files']

values = files[0].split('_')
fname = '_'.join(values[:2])
r_1 = int(values[2], 16)
s_1 = int(values[3], 16)
b_1 = int(values[4], 16)
h_1 = int(sha1(fname.encode()).hexdigest(), 16)

values = files[1].split('_')
fname = '_'.join(values[:2])
r_2 = int(values[2], 16)
s_2 = int(values[3], 16)
b_2 = int(values[4], 16)
h_2 = int(sha1(fname.encode()).hexdigest(), 16)

A_1 = 2 ** 200 * s_1
A_2 = 2 ** 192 * s_2
B_1 = 2 ** 56 * s_1 * b_1 - h_1
B_2 = 2 ** 56 * s_2 * b_2 - h_2

n = generator_256.order()

W = 2 ** 1024

M = Matrix(ZZ, [
    [
        r_2 * A_1 % n,
        r_1 * A_2 % n,
        r_2 * s_1 % n,
        r_1 * s_2 % n,
        n,
        (r_2 * B_1 - r_1 * B_2) % n
    ],
    [1, 0, 0, 0, 0, 0],
    [0, 1, 0, 0, 0, 0],
    [0, 0, 1, 0, 0, 0],
    [0, 0, 0, 1, 0, 0],
    [0, 0, 0, 0, 1, 0],
    [0, 0, 0, 0, 0, W],
]).transpose()

M[:, 0] *= W
L = M.LLL()
L[:, 0] /= W

row = L[-1]
assert row[0] == 0 and row[-1] == W

a_1 = int(abs(row[1]))
a_2 = int(abs(row[2]))
c_1 = int(abs(row[3]))
c_2 = int(abs(row[4]))

k_1 = 2 ** 200 * a_1 + 2 ** 56 * b_1 + c_1
k_2 = 2 ** 192 * a_2 + 2 ** 56 * b_2 + c_2

x = (s_1 * k_1 - h_1) * pow(r_1, -1, n) % n
assert x == (s_2 * k_2 - h_2) * pow(r_2, -1, n) % n

k = 1337
fname = 'subject_danbeer'
h = int(sha1(fname.encode()).hexdigest(), 16)
r = int((k * generator_256).x())
s = pow(k, -1, n) * (h + x * r) % n

io.sendlineafter(
    b'Options:\n1.List files\n2.Access a file\n',
    json.dumps({'option': 'access', 'fname': fname, 'r': hex(r), 's': hex(s)}).encode()
)

data = bytes.fromhex(json.loads(io.recvline().decode())['data']).decode()
io.success(f'{fname}:\n{data}')
