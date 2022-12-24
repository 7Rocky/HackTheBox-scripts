#!/usr/bin/env python3

from pwn import log, process, remote, sys
from sage.all import PolynomialRing, Zmod


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'server.py'])

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def main():
    io = get_process()

    io.recvuntil(b'You managed to retrieve: ')
    encrypted_passphrase = int(io.recvline().decode(), 16)

    log.info(f'Encrypted passphrase: {hex(encrypted_passphrase)}')

    io.sendlineafter(b'> ', b'1')
    io.recvline()

    e = 0x10001
    n = int(io.recvline().decode())
    log.info(f'{n = }')

    io.sendlineafter(b'> ', b'2')
    io.recvline()

    p_hint = int(io.recvline().decode())
    log.info(f'{p_hint = }')
    log.info(f'{hex(p_hint) = }')

    F = PolynomialRing(Zmod(n), names=('x', ))
    x = F._first_ngens(1)[0]

    f = x + p_hint
    x0 = f.small_roots(2 ** 256, beta=0.5)[0]

    p = int(x0) + p_hint

    assert n % p == 0

    q = n // p
    phi_n = (p - 1) * (q - 1)
    d = pow(e, -1, phi_n)
    m = pow(encrypted_passphrase, d, n)
    passphrase = bytes.fromhex(hex(m)[2:])

    log.success(f'Passphrase: {passphrase.decode()}')

    io.sendlineafter(b'> ', b'3')
    io.sendlineafter(b'Which vault would you like to open: ', b'vault_68')
    io.sendlineafter(b'Enter the passphrase: ', passphrase)
    io.recvline()

    log.success(f'Flag: {io.recvline().decode().strip()}')
    io.close()


if __name__ == '__main__':
    main()
