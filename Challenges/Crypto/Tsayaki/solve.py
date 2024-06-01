#!/usr/bin/env python3

from pwn import process, remote, sys, xor
from random import choices
from tea import Cipher as TEA


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'server.py'])
    
    host, port = sys.argv[1].split(':')
    return remote(host, port)


io = get_process()
io.recvuntil(b'Here is my special message: ')
server_message = bytes.fromhex(io.recvline().decode())

key = b'asdf' * 4
IV = b'\0' * 8

io.sendlineafter(b'Enter your target ciphertext (in hex) : ', b'00' * 20)
io.sendlineafter(b'Enter your encryption key (in hex) : ', key.hex().encode())

io.recvuntil(b'Hmm ... close enough, but ')
ct = bytes.fromhex(io.recvuntil(b' ', drop=True).decode())
IV = xor(server_message[:8], TEA(key, IV).decrypt(ct)[:8])
io.close()

io = get_process()
rounds = io.progress('Round')
io.recvuntil(b'Here is my special message: ')
server_message = bytes.fromhex(io.recvline().decode())

for r in range(10):
    rounds.status(f'{r + 1} / 10')
    randoms = [''.join(choices('01', k=31)), ''.join(choices('01', k=31)), ''.join(choices('01', k=31)), ''.join(choices('01', k=31))]

    key = int('0' + '0'.join(randoms), 2).to_bytes(16, 'big')
    ct = TEA(key, IV).encrypt(server_message)
    io.sendlineafter(b'Enter your target ciphertext (in hex) : ', ct.hex().encode())

    for a, b, c, d in [[0, 0, 0, 0], [0, 0, 1, 1], [1, 1, 0, 0], [1, 1, 1, 1]]:
        key = int(str(a) + randoms[0] + str(b) + randoms[1] + str(c) + randoms[2] + str(d) + randoms[3], 2).to_bytes(16, 'big')
        io.sendlineafter(b'Enter your encryption key (in hex) : ', key.hex().encode())


rounds.success('10 / 10')
io.success(io.recvline().decode())
