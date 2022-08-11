#!/usr/bin/env python3

from pwn import *
from hashlib import sha256

BLOCK_SIZE = 32


def get_process():
    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def decrypt_block(enc_block, plaintext):
    dec_block = b''

    for i in range(BLOCK_SIZE):
        val = (enc_block[i] - plaintext[i]) % 256
        dec_block += bytes([val])

    return dec_block


def main():
    p = get_process()

    p.sendlineafter(b'> ', b'cat secret.txt')
    ct = bytes.fromhex(p.recvline().strip().decode())

    block = b'Command executed: cat secret.txt'
    secret = block
    i = 0

    while b'}' not in secret:
        h = sha256(ct[32 * i : 32 * (i + 1)] + block).digest()
        block = decrypt_block(ct[32 * (i + 1) : 32 * (i + 2)], h)
        secret += block
        i += 1

    print(secret.decode())
    p.close()


if __name__ == '__main__':
    main()
