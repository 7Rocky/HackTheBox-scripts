#!/usr/bin/env python3

from pwn import log, remote, string, sys


def get_process():
    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    p = get_process()

    junk = b'B' * 4
    flag = ''
    flag_progress = log.progress('Flag')

    while '}' not in flag:
        for c in string.printable:
            payload = junk
            payload += (b'A' * 15 + flag.encode())[-15:] + c.encode()
            payload += b'A' * (15 - len(flag) % 16)

            p.sendlineafter(b'> ', payload.hex().encode())
            ct = p.recvline().strip()

            b = len(flag) // 16

            if ct[32:64] == ct[32 * (b + 2): 32 * (b + 3)]:
                flag += c
                flag_progress.status(flag)
                break


if __name__ == '__main__':
    main()
