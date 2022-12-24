#!/usr/bin/env python3

from pwn import log, process, remote, sys, xor


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'server.py'])

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def main():
    io = get_process()

    p_1_1 = b'Property: ' + bytes.fromhex('00' * 6)

    io.sendlineafter(b'Property: ', p_1_1[10:].hex().encode())
    e_1 = c_1_1 = bytes.fromhex(io.recvline().decode())

    p_2_1 = p_1_1
    p_2_2 = xor(e_1, p_1_1)

    io.sendlineafter(b'Property: ', (p_2_1 + p_2_2)[10:].hex().encode())
    e_2 = bytes.fromhex(io.recvline().decode())

    c_2_1 = c_1_1
    c_2_2 = xor(e_2, c_2_1)

    p_3_1 = p_2_1
    p_3_2 = p_2_2
    p_3_3 = xor(p_2_2, c_2_2)

    io.sendlineafter(b'Property: ', (p_3_1 + p_3_2 + p_3_3)[10:].hex().encode())
    io.recvline()
    log.success(f'Flag: {io.recvline().decode().strip()}')
    io.close()


if __name__ == '__main__':
    main()
