#!/usr/bin/env sage

from ast import literal_eval
from hashlib import sha256

from sage.all import *


with open('output.txt') as fp:
    pub = literal_eval(fp.readline().split(' = ')[1])
    mix = literal_eval(fp.readline().split(' = ')[1])

P, Q, R = map(ZZ, pub)
f = (P + Q) / (Q + R) + (Q + R) / (R + P) + (R + P) / (P + Q)

x, y, z = PolynomialRing(QQ, 'x, y, z').gens()
eq = (x + y) / (y + z) + (y + z) / (z + x) + (z + x) / (x + y) - f

F = EllipticCurve_from_cubic(eq.numerator(), [1, -1, -1])
Fi = F.inverse()

G = F((P, Q, R))
X = G.division_points(2)[0]
a, b, c = Fi(X)

cd = lcm(lcm(a.denominator(), b.denominator()), c.denominator())
p, q, r = ZZ(a * cd), ZZ(b * cd), ZZ(c * cd)

assert is_prime(p) and int(p).bit_length() <= 1024
assert is_prime(q) and int(q).bit_length() <= 1024
assert is_prime(r) and int(r).bit_length() <= 1024

n = p * q * r
nb = (n.bit_length() + 7) // 8
N = f.numerator()

d = pow(N, -1, (p - 1) * (q - 1) * (r - 1))
sp = pow(mix[0], d, n)
sm = pow(mix[1], d, n)

s1 = (sp + sm) * pow(2, -1, n) % n
s2 = (sp - sm) * pow(2, -1, n) % n

R = pow(s1, N, n)
c = pow(s2, N, n)
assert c.bit_length() <= nb

A, B = Matrix(ZZ, [[R, n], [1, 0]]).transpose().LLL()[0]
assert R == A * pow(B, -1, n) % n

g = 0
m, h = PolynomialRing(QQ, 'm, h').gens()

while True:
    g += 1

    I = Ideal([
        (m + h) ** 2 * (c + m) + (h + c) ** 2 * (m + h) + (c + m) ** 2 * (h + c) - g * A,
        (m + h) * (c + m) * (h + c) - g * B,
    ])

    for sol in I.variety():
        m = int(sol.get(m))
        h = int(sol.get(h))
        assert int(sha256(m.to_bytes(nb, 'big')).hexdigest(), 16) == h
        print(bytes.fromhex(hex(m)[2:]).decode())
        exit()
