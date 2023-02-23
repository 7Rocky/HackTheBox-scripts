#!/usr/bin/env python3

from Crypto.Util.number import long_to_bytes
from pwn import log, remote, sys
from sage.all import crt, discrete_log, EllipticCurve, factor, GF

a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
Fp = GF(p)
host, port = sys.argv[1].split(':')


def get_S(b):
    E = EllipticCurve(Fp, [a, b])
    order = E.order()
    factors = factor(order)
    G = E.gens()[0]
    log.info(f'ord(E_{b}) = {factors}')

    io = remote(host, int(port))

    io.sendlineafter(b'Awaiting public key of the client...\n', f'{G[0]} {G[1]}'.encode())
    io.recvuntil(b'Shared secret: ')
    S_tuple = eval(io.recvline().decode())
    io.close()

    return order, G, factors, E(S_tuple)


def get_dlogs(S, G, order, factors, new_factors, dlogs):
    for prime, exponent in factors:
        log.info(f'{prime = }, {exponent = }')
        new_factors.append(prime ** exponent)
        t = order // new_factors[-1]
        dlogs.append(discrete_log(t * S, t * G, operation='+'))


def main():
    order_0, G_0, factors_0, S_0 = get_S(0)
    order_1, G_1, factors_1, S_1 = get_S(1)
    order_4, G_4, factors_4, S_4 = get_S(4)

    new_factors, dlogs = [], []

    get_dlogs(S_0, G_0, order_0, factors_0[:-2], new_factors, dlogs)
    get_dlogs(S_1, G_1, order_1, factors_1[:-1], new_factors, dlogs)
    get_dlogs(S_4, G_4, order_4, factors_4[1:-3], new_factors, dlogs)

    flag = crt(dlogs, new_factors)
    log.success(long_to_bytes(flag).decode())


if __name__ == '__main__':
    main()
