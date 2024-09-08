#!/usr/bin/env python3

from ast import literal_eval
from pwn import log, remote, sys

from sage.all import crt, EllipticCurve, gcd, GF, Integer, Matrix, QQ

from Crypto.Util.number import long_to_bytes


def get_process() -> remote:
    host, port = sys.argv[1].split(':')
    return remote(host, port, level='CRITICAL')


def find_integer_relation(x: float) -> tuple[int, int, int]:
    M = Matrix(QQ, [
        [x ** 2, x, 1],
        [1,      0, 0],
        [0,      1, 0],
        [0,      0, 1],
    ])

    M[0, :] *= 10 ** 13

    L = M.T.LLL()

    for row in L.rows():
        ai, bi, ci = map(int, row[1:4])
        res = ai * x ** 2 + bi * x + ci
        res *= 10 ** 13

        if int(res) == 0 and all(0 < abs(z) <= 60 for z in [ai, bi, ci]):
            return ai, bi, ci

    return 0, 0, 0



def get_flag_order() -> tuple[Integer, Integer]:
    io = get_process()
    a = b = c = 0

    for r in range(7):
        round_prog.status(str(r + 1))
        io.recvuntil(b'x = ')
        x = float(io.recvlineS())
        a, b, c = find_integer_relation(x)

        if a == b == c == 0:
            io.close()
            return Integer(0), Integer(0)

        io.sendlineafter(b'a: ', str(a).encode())
        io.sendlineafter(b'b: ', str(b).encode())
        io.sendlineafter(b'c: ', str(c).encode())

    io.recvuntil(b'G = ')
    Gx, Gy = literal_eval(io.recvlineS())
    io.recvuntil(b'Gn = ')
    nGx, nGy = literal_eval(io.recvlineS())
    io.recvuntil(b'p = ')
    p = literal_eval(io.recvlineS())
    io.close()

    E = EllipticCurve(GF(p), [b, c])
    G = E(Gx, Gy)
    nG = E(nGx, nGy)
    n = nG.log(G)
    order = G.order()
    return n, order


round_prog = log.progress('Round')
samples_prog = log.progress('Samples')
flag_prog = log.progress('Flag')

flags, orders = [], []
flag = b''

while not flag.startswith(b'HTB{'):
    samples_prog.status(str(len(flags)))

    try:
        f, o = get_flag_order()
    except EOFError:
        continue

    if f == o == 0:
        continue

    for oo in orders:
        if gcd(oo, o) != 1:
            break
    else:
        flags.append(f)
        orders.append(o)

        n = int(crt(flags, orders))
        flag = long_to_bytes(n)
        flag_prog.status(str(flag))

flag_prog.success(flag.decode())
