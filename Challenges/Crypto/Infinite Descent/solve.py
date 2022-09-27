#!/usr/bin/env python3

from Crypto.PublicKey import RSA
from Crypto.Util.number import isPrime

from gmpy2 import iroot

from AESbootstrap import gen_and_check


def main():
    key = RSA.import_key('''-----BEGIN PUBLIC KEY-----
    MIGeMA0GCSqGSIb3DQEBAQUAA4GMADCBiAKBgFbDk+zYy1tbjwPpsTWbYjIfBtZk
    walARbJxLg6QhyalsGnBx064VFIH9XIKzPK/Dt1RzMO68gy7zLOiyipPtYb2n0M6
    WcdDGgw9J9+xx4HjXZCHx4h4zQhfQeOYymeSPewXJOe+GT31ymz6/Q1Ulyq/jWnD
    XZogxfbXi6bIwuN7AgMBAAE=
    -----END PUBLIC KEY-----
    ''')

    p = iroot(key.n, 2)[0]

    while not isPrime(p):
        p += 1

    q = p - 1

    while not isPrime(q):
        q -= 1

    assert key.n == p * q

    c = 41296290787170212566581926747559000694979534392034439796933335542554551981322424774631715454669002723657175134418412556653226439790475349107756702973735895193117931356004359775501074138668004417061809481535231402802835349794859992556874148430578703014721700812262863679987426564893631600671862958451813895661

    phi_n = (p - 1) * (q - 1)
    d = pow(key.e, -1, phi_n)
    m = pow(c, d, key.n)
    m_str = str(m)

    m_numbers = [int(m_str[i:i+3]) for i in range(0, len(m_str), 3)]
    flag = ''

    for m_n in m_numbers:
        list = str(bin(gen_and_check(m_n)))
        candidate = list[2::]
        candidate = candidate.zfill(8)
        flag += chr(int(candidate, 2))

    print(flag)


if __name__ == '__main__':
    main()
