#!/usr/bin/env python3

from pwn import log, process, remote, sys


def legendre(x: int, p: int) -> int:
    return pow(x, (p - 1) // 2, p)


def tonelli(n: int, p: int) -> int:
    assert legendre(n, p) == 1, 'not a square (mod p)'
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    if s == 1:
        return pow(n, (p + 1) // 4, p)
    for z in range(2, p):
        if p - 1 == legendre(z, p):
            break
    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    t2 = 0
    while (t - 1) % p != 0:
        t2 = (t * t) % p
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r


def fast_turbonacci(n: int, p: int, b: int, c: int) -> int:
    sqrt_delta = tonelli((pow(b, 2, p) + 4 * c), p)
    r1 = (b + sqrt_delta) * pow(2, -1, p) % p
    r2 = (b - sqrt_delta) * pow(2, -1, p) % p
    return (pow(r1, n, p) - pow(r2, n, p)) * pow(r1 - r2, -1, p) % p


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'challenge/server.py'])

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    io = get_process()
    io.recvuntil(b'p = ')
    p = int(io.recvline().decode())

    io.recvuntil(b'b = ')
    b = int(io.recvline().decode())

    io.recvuntil(b'c = ')
    c = int(io.recvline().decode())

    io.recvuntil(b'nonce = ')
    nonce = int(io.recvuntil(b' ').strip().decode())

    otp = fast_turbonacci(nonce, p, b, c)

    io.sendlineafter(b'OTP: ', str(otp).encode())

    io.sendlineafter(b'> ', b'1')
    io.recvuntil(b'ct = ')
    flag_enc = int(io.recvline().strip())

    pt1 = b'a'
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'pt = ', pt1)
    io.recvuntil(b'ct = ')
    ct1 = int(io.recvline().strip())

    pt2 = b'b'
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b'pt = ', pt2)
    io.recvuntil(b'ct = ')
    ct2 = int(io.recvline().strip())

    io.sendlineafter(b'> ', b'3')
    io.close()

    m = ct2 - ct1
    k = (ord(pt1) - ct1 * pow(m, -1, p)) % p

    flag = (k + flag_enc * pow(m, -1, p)) % p
    log.success(bytes.fromhex(hex(flag)[2:]).decode())


if __name__ == '__main__':
    main()
