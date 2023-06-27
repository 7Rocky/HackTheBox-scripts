#!/usr/bin/env python3

import json

from hashlib import sha256
from sage.all import *
from pwn import *

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from Crypto.Util.Padding import unpad


def bivariate(pol, XX, YY, kk=4):
    N = pol.parent().characteristic()

    f = pol.change_ring(ZZ)
    PR, (x, y) = f.parent().objgens()

    idx = [(k-i, i) for k in range(kk+1) for i in range(k+1)]
    monomials = list(map(lambda t: PR(x**t[0]*y**t[1]), idx))
    # collect the shift-polynomials
    g = []
    for h, i in idx:
        if h == 0:
            g.append(y**h * x**i * N)
        else:
            g.append(y**(h-1) * x**i * f)

    # construct lattice basis
    M = Matrix(ZZ, len(g))
    for row in range(M.nrows()):
        for col in range(M.ncols()):
            h, i = idx[col]
            M[row, col] = g[row][h, i] * XX**h * YY**i

    # LLL
    B = M.LLL()

    PX = PolynomialRing(ZZ, 'xs')
    xs = PX.gen()
    PY = PolynomialRing(ZZ, 'ys')
    ys = PY.gen()

    # Transform LLL-reduced vectors to polynomials
    H = [(i, PR(0)) for i in range(B.nrows())]
    H = dict(H)
    for i in range(B.nrows()):
        for j in range(B.ncols()):
            H[i] += PR((monomials[j]*B[i, j]) / monomials[j](XX, YY))

    # Find the root
    poly1 = H[0].resultant(H[1], y).subs(x=xs)
    poly2 = H[0].resultant(H[2], y).subs(x=xs)
    poly = gcd(poly1, poly2)
    x_root = poly.roots()[0][0]

    poly1 = H[0].resultant(H[1], x).subs(y=ys)
    poly2 = H[0].resultant(H[2], x).subs(y=ys)
    poly = gcd(poly1, poly2)
    y_root = poly.roots()[0][0]

    return x_root, y_root


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'server.py'])

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def main():
    io = get_process()
    io.recvline()

    data = json.loads(io.recvline().decode())
    x_p, y_p = int(data['x'], 16), int(data['y'], 16)

    io.sendlineafter(b'> ', b'2')
    data = json.loads(io.recvline().decode())
    iv, enc = bytes.fromhex(data['iv']), bytes.fromhex(data['enc'])

    a_highs, b_highs = [], []

    for _ in range(50):
        io.sendlineafter(b'> ', b'1')
        data = json.loads(io.recvline().decode())

        p = int(data['p'], 16)
        a_highs.append(int(data['a'], 16))
        b_highs.append(int(data['b'], 16))

    aH, bH = sorted(a_highs)[-1], sorted(b_highs)[-1]

    r_mean = 512 - aH.bit_length()
    found = False

    for r in range(r_mean - 5, r_mean + 5):
        PR = PolynomialRing(Zmod(p), names='x,y')
        x, y = PR.gens()
        S = y_p ** 2 - x_p ** 3 - (aH << r) * x_p - (bH << r)

        pol = x_p * x + y - S

        try:
            aL, bL = bivariate(pol, 2 ** r, 2 ** r)
            a, b = int(aL + (aH << r)), int(bL + (bH << r))

            if (y_p ** 2 - x_p ** 3 - a * x_p - b) % p == 0:
                found = True
                break
        except IndexError:
            pass

    if found:
        key = sha256(long_to_bytes(pow(a, b, p))).digest()[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        io.success(unpad(cipher.decrypt(enc), 16).decode())
    else:
        io.failure('Not found')


if __name__ == '__main__':
    main()
