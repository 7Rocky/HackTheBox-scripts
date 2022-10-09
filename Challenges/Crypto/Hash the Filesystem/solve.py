#!/usr/bin/env python3

import json

from pwn import log, remote, sys, xor
from Crypto.Util.Padding import pad


def forward_hash(i):
    acc = 2870177450012600261
    acc += i * 14029467366897019727
    acc %= 2 ** 64
    acc = (acc << 31) | (acc >> 33)
    acc *= 11400714785074694791

    return acc % (2 ** 64)


def reverse_hash(expected, state):
    acc = expected
    acc -= 2 ^ 2870177450012600261 ^ 3527539
    acc *= 614540362697595703
    acc %= 2 ** 64
    acc = (acc & 0x7fffffff) << 33 | (acc >> 31)
    acc -= state
    acc *= 839798700976720815

    return acc % (2 ** 64)


def find_collision(expected):
    if expected.startswith('ff'):
        expected = '-' + expected[2:]

    expected = int(expected, 16)
    P = 2305843009213693951
    second = P + 1
    first = 0

    while second >= P:
        first += 1
        second = reverse_hash(expected, forward_hash(first))

    return first, second


def main():
    host, port = sys.argv[1].split(':')
    io = remote(host, int(port))

    user = 'rocky'
    io.sendlineafter(b'> ', user.encode())
    now = str(time.time())
    io.recvuntil(b'Your token is: ')

    token_pt = json.dumps({'username': user, 'timestamp': now})
    token_ct = bytes.fromhex(io.recvline().strip().decode())

    stream = xor(pad(token_pt.encode(), 16), token_ct)

    admin_token_pt = json.dumps({'username': 'admin', 'timestamp': now})
    admin_token_ct = xor(stream, pad(admin_token_pt.encode(), 16))

    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'Submit your token.\n', json.dumps(
        {'token': admin_token_ct.hex()}).encode())

    files = set(json.loads(io.recv().decode())['files'])
    log.info(f'Files: {files}')

    for file in files:
        fname = find_collision(file)

        io.sendlineafter(b'> ', b'3')
        io.sendlineafter(b'Submit your token and passphrase.\n', json.dumps(
            {'token': admin_token_ct.hex(), 'passphrase': fname}).encode())
        content = bytes.fromhex(json.loads(io.recvline().decode())['content'])

        if b'HTB{' in content:
            log.success(f'Flag: {content.decode().strip()}')
            break

    io.close()


if __name__ == '__main__':
    main()
