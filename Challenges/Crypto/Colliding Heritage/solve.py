#!/usr/bin/env python3

from Crypto.Util.number import long_to_bytes, bytes_to_long
from hashlib import md5
from pwn import remote, sys


p = 0x16dd987483c08aefa88f28147702e51eb
q = (p - 1) // 2
g = 3


def H(msg):
    return bytes_to_long(md5(msg).digest()) % q


def main():
    host, port = sys.argv[1].split(':')
    io = remote(host, port)

    msg1 = 'd131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70'
    msg2 = 'd131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70'

    io.sendlineafter(b'> ', b'S')
    io.sendlineafter(b'Enter message> ', msg1.encode())
    io.recvuntil(b'Signature: ')
    s1, e1 = eval(io.recvline().decode())

    io.sendlineafter(b'> ', b'S')
    io.sendlineafter(b'Enter message> ', msg2.encode())
    io.recvuntil(b'Signature: ')
    s2, e2 = eval(io.recvline().decode())

    x = (s2 - s1) * pow(e1 - e2, -1, q) % q

    def sign(msg):
        k = H(msg + long_to_bytes(x))
        r = pow(g, k, p) % q
        e = H(long_to_bytes(r) + msg)
        s = (k - x * e) % q
        return (s, e)

    s, e = sign(b'I am the left hand')

    io.sendlineafter(b'> ', b'V')
    io.sendlineafter(b'Enter message> ', b'I am the left hand'.hex().encode())
    io.sendlineafter(b'Enter s> ', str(s).encode())
    io.sendlineafter(b'Enter e> ', str(e).encode())

    io.success(io.recvline().decode())


if __name__ == '__main__':
    main()
