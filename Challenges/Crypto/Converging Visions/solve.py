#!/usr/bin/env python3

from sage.all import *
from pwn import process, remote, sys
from Crypto.Util.number import isPrime


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'server.py'])

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def SmartAttack(P, Q, p):
    E = P.curve()
    Eqp = EllipticCurve(
        Qp(p, 2), [ZZ(t) + randint(0, p)*p for t in E.a_invariants()])

    P_Qps = Eqp.lift_x(ZZ(P.xy()[0]), all=True)
    for P_Qp in P_Qps:
        if GF(p)(P_Qp.xy()[1]) == P.xy()[1]:
            break

    Q_Qps = Eqp.lift_x(ZZ(Q.xy()[0]), all=True)
    for Q_Qp in Q_Qps:
        if GF(p)(Q_Qp.xy()[1]) == Q.xy()[1]:
            break

    p_times_P = p*P_Qp
    p_times_Q = p*Q_Qp

    x_P, y_P = p_times_P.xy()
    x_Q, y_Q = p_times_Q.xy()

    phi_P = -(x_P/y_P)
    phi_Q = -(x_Q/y_Q)
    k = phi_Q/phi_P
    return ZZ(k)


def main():
    io = get_process()

    left, right = 2 ** 16, 2 ** 256
    m = (left + right) // 2

    while left < right - 1:
        m = (left + right) // 2

        io.sendlineafter(b'> ', b'1')
        io.sendlineafter(b'x : ', str(m).encode())

        data = io.recvline()
        if b'Coordinate greater than curve modulus' in data:
            right = m - 1
        else:
            left = m + 1

    p = m + 1
    io.info(f'Got modulus {p = }')
    assert isPrime(p)

    points = []
    x = 0

    while len(points) < 2:
        io.sendlineafter(b'> ', b'1')
        io.sendlineafter(b'x : ', str(x).encode())

        data = io.recvline()

        if b'Point confirmed on curve' in data:
            point = tuple(
                map(int, data.decode().replace(')', '').split(', ')[1:]))
            points.append(point)

        x += 1

    (x1, y1), (x2, y2) = points
    a = (y1 ** 2 - y2 ** 2 - x1 ** 3 + x2 ** 3) * pow(x1 - x2, -1, p) % p
    b = (y1 ** 2 - x1 ** 3 - a * x1) % p

    io.info(f'Got parameters {a = } and {b = }')

    x2 = 6
    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'x : ', str(x2).encode())

    E = EllipticCurve(GF(p), [a, b])
    EP = E.gens()[0]

    io.sendlineafter(b'> ', b'1')
    io.sendlineafter(b'x : ', str(EP[0]).encode())

    io.sendlineafter(b'> ', b'2')
    io.recvline()
    point = tuple(
        map(int, io.recvline().decode().replace(')', '').split(', ')[1:]))
    enc_seed_EP = E(point[0], point[1])

    enc_seed = SmartAttack(EP, enc_seed_EP, p)
    io.info(f'Smart Attack -> {enc_seed = }')
    seed = int(GF(p)(enc_seed).nth_root(2))
    c = int.from_bytes(b'Coordinates lost in space', 'big')
    next_seed = (a * pow(seed, 3) + b * seed + c) % p

    curr_P = EP * seed
    next_P = curr_P * next_seed
    io.info(f'Trying next point {next_P}...')

    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'x: ', str(next_P[0]).encode())
    io.sendlineafter(b'y: ', str(next_P[1]).encode())

    io.success(io.recv().decode())


if __name__ == '__main__':
    main()
