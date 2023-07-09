#!/usr/bin/env python3

from pwn import process


def main():
    p = process(['gdb', '-q', 'vault'])
    gef = b'gef\xe2\x9e\xa4  \x01\x1b[0m\x02'

    p.sendlineafter(gef, b'break *0x5555555603a1')
    p.sendlineafter(gef, b'run')

    flag = []
    prog = p.progress('Flag')

    for _ in range(0x19):
        prog.status(''.join(flag))
        p.sendlineafter(gef, b'set $rax = $rcx')
        p.sendlineafter(gef, b'p/c $rax')

        al = p.recvline().decode().strip().split()[-1]
        flag.append(chr(int(al, 16)))

        p.sendlineafter(gef, b'continue')

    prog.success(''.join(flag))


if __name__ == '__main__':
    main()
