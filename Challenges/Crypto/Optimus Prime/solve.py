#!/usr/bin/env python3

from math import gcd
from pwn import remote, sys


def get_process():
    if len(sys.argv) != 2:
        print(f'Usage: python3 {sys.argv[0]} <ip:port>')
        exit(1)

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def get_public_key(p) -> int:
    p.sendlineafter(b'Enter the option: ', b'4')
    p.recvuntil(b'PUBLIC KEY: ')
    return int(p.recvline())


def get_encrypted_password(p) -> int:
    p.recvuntil(b'ENCRYPTED PASSWORD: ')
    return int(p.recvline())


def main():
    r = get_process()

    n1 = get_public_key(r)
    c1 = get_encrypted_password(r)

    r.close()
    r = get_process()

    n2 = get_public_key(r)
    c2 = get_encrypted_password(r)

    px = gcd(n1, n2)
    p2 = n2 // px

    e = 65537
    phi_n2 = (px - 1) * (p2 - 1)
    d2 = pow(e, -1, phi_n2)

    m = bytes.fromhex(hex(pow(c2, d2, n2))[2:])

    r.sendlineafter(b'Please use it to proceed: ', m)
    r.recvuntil(b'ACCESS GRANTED: ')
    print(r.recvline().decode())


if __name__ == '__main__':
    main()
