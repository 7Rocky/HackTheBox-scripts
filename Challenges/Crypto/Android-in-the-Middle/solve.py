#!/usr/bin/env python3

import hashlib

from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes

from pwn import remote, sys


def encrypt(encrypted, shared_secret):
    key = hashlib.md5(long_to_bytes(shared_secret)).digest()
    cipher = AES.new(key, AES.MODE_ECB)
    message = cipher.encrypt(encrypted)
    return message


def main():
    host, port = sys.argv[1].split(':')
    p = remote(host, int(port))

    encrypted_message = encrypt(b'Initialization Sequence - Code 0', 1)

    p.sendlineafter(b'Enter The Public Key of The Memory: ', b'1')
    p.sendlineafter(b'Enter The Encrypted Initialization Sequence: ', encrypted_message.hex().encode())

    p.recvline()
    p.recvline()
    print(p.recv().decode())


if __name__ == '__main__':
    main()
