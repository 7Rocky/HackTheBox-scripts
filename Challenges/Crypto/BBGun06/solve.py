#!/usr/bin/env python3

from Crypto.PublicKey import RSA
from Crypto.Util.number import long_to_bytes
from gmpy2 import iroot
from pwn import log, re, remote, sys


def main():
    if len(sys.argv) != 2:
        log.warning(f'Usage: python3 {sys.argv[0]} <host:port>')
        exit(1)

    host, port = sys.argv[1].split(':')
    r = remote(host, int(port))

    r.recvuntil(b'certificate: \n')
    cert = RSA.import_key(r.recvuntil(b'-----END PUBLIC KEY-----').decode())
    n, e = cert.n, cert.e

    forged_min = int((b'\x00\x01' + b'\xff' *   1 + b'\x000!0\t\x06\x05+\x0e\x03\x02\x1a\x05\x00\x04\x14\xdb}\xdd?yeA\xdaO\x80]yHo\xd3w\x07\x9c2p').ljust(256, b'\x00').hex(), 16)
    forged_max = int((b'\x00\x01' + b'\xff' * 217 + b'\x000!0\t\x06\x05+\x0e\x03\x02\x1a\x05\x00\x04\x14\xdb}\xdd?yeA\xdaO\x80]yHo\xd3w\x07\x9c2p').ljust(256, b'\xff').hex(), 16)

    perfect_cube_range = range(iroot(forged_min, e)[0], iroot(forged_max, e)[0])

    regex = re.compile(b'\x00\x01\xff+?\x00(.{15})(.{20})', re.DOTALL)
    keylength = len(long_to_bytes(n))

    for t in perfect_cube_range:
        clearsig = (t ** e).to_bytes(keylength, 'big')
        m = regex.match(clearsig)

        if m and m.groups() == (b'0!0\t\x06\x05+\x0e\x03\x02\x1a\x05\x00\x04\x14', b'\xdb}\xdd?yeA\xdaO\x80]yHo\xd3w\x07\x9c2p'):
            break

    r.sendafter(b'Enter the signature as hex: ', hex(t)[2:].encode())
    log.success(f'Flag: {r.recv().decode()}')
    r.close()


if __name__ == '__main__':
    main()
