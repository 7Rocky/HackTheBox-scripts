#!/usr/bin/env python3

from pwn import context, log
from random import randint

context.binary = 'nreport_patched'
context.log_level = 'CRITICAL'


def main():
    while True:
        test_bytes = [randint(0x30, 0x7e) for _ in range(5)]
        test_token = bytes(test_bytes[:3]) + b'A' * 6 + \
            bytes([test_bytes[3]]) + b'A' * 3 + bytes([test_bytes[4]])

        p = context.binary.process()
        p.recv()
        p.sendline(test_token)
        msg = p.recv(timeout=1)

        if b'Invalid Token' not in msg:
            with context.local(log_level='DEBUG'):
                print()
                log.success(f'Valid token: {test_token.decode()}')

            p.close()
            break

        p.close()


if __name__ == '__main__':
    main()
