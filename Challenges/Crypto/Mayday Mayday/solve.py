#!/usr/bin/env python3

from sage.all import assume, PolynomialRing, solve, var, Zmod


with open('output.txt') as f:
    n = int(f.readline().split(' = ')[1], 16)
    e = int(f.readline().split(' = ')[1], 16)
    c = int(f.readline().split(' = ')[1], 16)
    dp_H = int(f.readline().split(' = ')[1], 16) << 512
    dq_H = int(f.readline().split(' = ')[1], 16) << 512


A = (e * dp_H - 1) * (e * dq_H - 1) // n + 1
S = (A * (1 - n) + 1) % e

kp_var, kq_var = var('kp, kq')
assume(kp_var, 'integer')
assume(kq_var, 'integer')

possible_kp_kq = []

while True:
    sols = solve([
        kp_var * kq_var == A,
        kp_var + kq_var == S
    ], kp_var, kq_var, algorithm='sympy')

    if not sols:
        S += e
        continue

    for sol in sols:
        kp, kq = map(int, sol.values())
        possible_kp_kq.append((kp, kq))

    break


x = PolynomialRing(Zmod(n), 'x').gens()[0]

for kp, kq in possible_kp_kq:
    d_kp = (pow(e, -1, kp) - dp_H) % kp
    P = (e * (dp_H + kp * x + d_kp) - 1 + kp).monic()
    roots = P.small_roots(beta=0.5)

    if roots and roots[0] != n:
        dp_L = kp * roots[0] + d_kp
        p = int((e * (dp_H + dp_L) - 1 + kp) // kp)
        assert n % p == 0 and 1 < p < n
        q = n // p
        d = pow(e, -1, (p - 1) * (q - 1))
        m = pow(c, d, n)
        print(bytes.fromhex(hex(m)[2:]).decode())
        break
