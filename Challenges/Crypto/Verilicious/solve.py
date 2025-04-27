#!/usr/bin/env python3

from ast import literal_eval

from Crypto.PublicKey import RSA

from sage.all import Matrix, QQ


with open("pubkey.pem") as pk, open("output.txt") as o:
    key = RSA.import_key(pk.read())
    R = literal_eval(o.read().split('R = ')[1])

n = key.n

k = -(-n.bit_length() // 8)
B = 2 ** (8 * (k - 2))

W = 3 * B - 1
H = 2 * B + B // 2

a = [H] * len(R)
t = list(sorted(R))

M = Matrix(QQ, [
    *[
        [0] * i + [n] + [0] * (len(R) - i + 1) for i in range(len(R))
    ],
    t + [W / n, 0],
    a + [0, W],
])

L = M.LLL()
row = L[-1]
assert abs(row[-1]) == W

for i in range(len(R) - 1):
    m = int(abs(row[i]) + a[i]) * pow(R[i], -1, n) % n
    M = m.to_bytes(128, 'big')

    if M.startswith(b'\0\x02') and b'HTB' in M:
        print(M.split(b'\0')[-1].decode())
        break
