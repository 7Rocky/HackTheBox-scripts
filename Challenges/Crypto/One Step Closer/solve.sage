#!/usr/bin/env sage

import requests
import sys


def composite_modulus_gcd(f, g):
    if g == 0:
        return f.monic()

    return composite_modulus_gcd(g, f % g)


def franklin_reiter(n, e, ct1, ct2, a1, a2, b1, b2):
    P.<x> = PolynomialRing(Zmod(n))
    f = (a1 * x + b1) ^ e - ct1
    g = (a2 * x + b2) ^ e - ct2

    return -composite_modulus_gcd(f, g).coefficients()[0] % n


def main():
    host = sys.argv[1]

    r = requests.get(f'http://{host}/api/get_flag')

    ct1 = int(r.json().get('ct'), 16)
    n = int(r.json().get('n'), 16)
    e = int(r.json().get('e'), 16)
    a1 = int(r.json().get('a'), 16)
    b1 = int(r.json().get('b'), 16)

    r = requests.get(f'http://{host}/api/get_flag')

    ct2 = int(r.json().get('ct'), 16)
    a2 = int(r.json().get('a'), 16)
    b2 = int(r.json().get('b'), 16)

    m = franklin_reiter(n, e, ct1, ct2, a1, a2, b1, b2)
    print(bytes.fromhex(hex(m)[2:]).decode())


if __name__ == '__main__':
    main()
