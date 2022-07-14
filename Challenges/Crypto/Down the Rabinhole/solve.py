#!/usr/bin/env python3

import math


def main():
    with open('out.txt') as f:
        n1, c1, c2, n2, c3, c4, L = map(int, f.read().splitlines())

    C = math.gcd(n1 - 4, n2 - 4) // 3

    K = 256 - math.floor(L / 2)
    P = int(hex(K)[2:] * K, 16)

    X = (c2 - P ** 2 - P * C) * pow(256 ** K, -1, n1) % n1
    m1 = (X - 256 ** K * c1) * pow(2 * P + C - C * 256 ** K, -1, n1) % n1

    K = 256 - math.ceil(L / 2)
    P = int(hex(K)[2:] * K, 16)

    Y = (c4 - P ** 2 - P * C) * pow(256 ** K, -1, n2) % n2
    m2 = (Y - 256 ** K * c3) * pow(2 * P + C - C * 256 ** K, -1, n2) % n2

    print(bytes.fromhex(hex(m1)[2:] + hex(m2)[2:]))


if __name__ == '__main__':
    main()
