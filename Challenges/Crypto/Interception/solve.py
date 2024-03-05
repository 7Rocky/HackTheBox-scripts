#!/usr/bin/env python3

from hashlib import sha256
from math import gcd
from pwn import process, remote, sys
from sage.all import PolynomialRing, primes, Zmod

from Crypto.Util.number import bytes_to_long, long_to_bytes


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'server.py'])

    host, port = sys.argv[1].split(':')
    return remote(host, port)


e = 65537

guessed_greet = bytes_to_long(b'Hey!')
guessed_greet_e = guessed_greet ** e

guessed_ans = bytes_to_long(b'Bye!')
guessed_ans_e = guessed_ans ** e

n = 0

while True:
    io = get_process()
    io.recvuntil(b'We say : ')
    enc_greet = int(io.recvline().decode(), 16)
    enc_anss = set()

    while len(enc_anss) < 3:
        io.sendlineafter(b'> ', b'S')
        io.sendlineafter(b'You say : ', hex(enc_greet).encode())
        io.recvuntil(b'Nice! We say : ')
        enc_anss.add(int(io.recvline().decode(), 16))

    n = max(gcd(guessed_greet_e - enc_greet, guessed_ans_e - enc_ans) for enc_ans in enc_anss)

    for p in primes(100):
        if n % p == 0:
            n //= p

    if n.bit_length() == 2048 and n & 1:
        io.success(f'Found {n = }')
        break

    io.close()

io.sendlineafter(b'> ', b'F')
io.sendlineafter(
    b'Before giving you the token, you must prove me that you know the public key : ',
    sha256(str(n).encode()).hexdigest().encode(),
)

io.recvuntil(b'Here is your token : ')
d = 1024 - 643
token = int(io.recvline().decode())
q_H = (token >> d) << d

x = PolynomialRing(Zmod(n), names='x').gens()[0]

q_L = int((x + q_H).small_roots(X=2 ** d, beta=0.499)[0])

q = q_H + q_L
assert n % q == 0 and 1 < q < n
p = n // q
io.success(f'Found {p = }')
io.success(f'Found {q = }')

phi_n = (p - 1) * (q - 1)

exp = pow(0xdeadbeef, n, phi_n)
key = long_to_bytes(pow(0x1337, exp, n))[:16]

io.sendlineafter(b'> ', b'R')
io.sendlineafter(b'Enter decryption key : ', key.hex().encode())
io.success(io.recvall().decode())
