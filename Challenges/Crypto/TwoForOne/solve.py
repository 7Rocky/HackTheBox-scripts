#!/usr/bin/env python3

from base64 import b64decode
from Crypto.PublicKey import RSA


def extended_gcd(a, b):
    if a % b:
        u, v, d = extended_gcd(b, a % b)
        return v, (d - a * v) // b, d

    return 0, 1, b


def main():
    c1 = int(b64decode(open('message1').read()).hex(), 16)
    c2 = int(b64decode(open('message2').read()).hex(), 16)

    key1 = RSA.importKey(open('key1.pem').read())
    key2 = RSA.importKey(open('key2.pem').read())

    n = key1.n
    e1, e2 = key1.e, key2.e

    u, v, _ = extended_gcd(e1, e2)

    m = pow(c1, u, n) * pow(c2, v, n) % n

    print(bytes.fromhex(format(m, '0x')).decode())


if __name__ == '__main__':
    main()
