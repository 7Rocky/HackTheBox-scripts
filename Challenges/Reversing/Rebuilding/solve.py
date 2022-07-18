#!/usr/bin/env python3

from pwn import log, process


def main():
    p = process(['gdb', '-q', 'rebuilding'])
    gef = b'gef\xe2\x9e\xa4  \x01\x1b[0m\x02'

    p.sendlineafter(gef, b'break *main+303')
    p.sendlineafter(gef, b'run ' + b'A' * 32)

    flag = []
    prog = log.progress('Flag')

    for _ in range(32):
        prog.status(''.join(flag))
        p.sendlineafter(gef, b'set $rax = $rcx')
        p.sendlineafter(gef, b'p/c $rcx')

        rcx = p.recvline().decode().strip().split()[-1]
        flag.append(chr(int(rcx, 16)))

        p.sendlineafter(gef, b'continue')

    p.close()
    prog.success(''.join(flag) + '}')


if __name__ == '__main__':
    main()
