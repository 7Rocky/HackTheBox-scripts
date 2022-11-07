#!/usr/bin/env python3

from pwn import remote, sys


def main():
    host, port = sys.argv[1].split(':')
    p = remote(host, int(port))

    p.recvuntil(b'Find a message that generate the same hash as this one: ')
    target = p.recvline().strip().decode()
    original_message = b"pumpkin_spice_latte!"

    message = original_message.replace(b'_', b'\xdf')
    p.sendlineafter(b'Enter your message: ', message.hex().encode())
    p.recvline()
    answer = p.recvline()

    while b'Conditions not satisfied!' in answer:
        p.sendlineafter(b'Enter your message: ', message.hex().encode())
        p.recvline()
        answer = p.recvline(2)

    p.close()
    print(answer.decode().strip())


if __name__ == '__main__':
    main()
