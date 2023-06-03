#!/usr/bin/env python3

from pwn import log, process


def main():
    p = process(['gdb', '-q', 'headache'])
    gef = b'gef\xe2\x9e\xa4  \x01\x1b[0m\x02'

    p.sendlineafter(gef, b'catch syscall ptrace')
    p.sendlineafter(gef, b'run')

    for i in range(4):
        p.sendlineafter(gef, b'set $rax = 0')

        if i == 3:
            p.sendlineafter(gef, b'break *0x555555556076')
            p.sendlineafter(gef, b'break *0x555555556646')

        p.sendlineafter(gef, b'continue')

    p.recv()
    p.sendline(b'A' * 20)
    p.sendlineafter(gef, b'continue')

    flag = []
    prog = log.progress('Flag')

    for _ in range(20):
        prog.status(''.join(flag))
        p.sendlineafter(gef, b'set $rax = $rdx')
        p.sendlineafter(gef, b'p/x $rdx')

        rdx = p.recvline().decode().strip().split()[-1]
        flag.append(chr(int(rdx, 16)))

        p.sendlineafter(gef, b'continue')

    p.close()

    prog.success(''.join(flag))


if __name__ == '__main__':
    main()
