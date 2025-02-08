#!/usr/bin/env python3

import json

from pwn import hashlib, process, remote, sys

from Crypto.Util.Padding import pad
from Crypto.Cipher import AES

from helpers import BOB_MR_DERIVATION, KEY_DERIVATION


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'server.py'])

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def generate_shared_key(measurement_basis, frames, ambiguous_frames, sifting_strings):
    shared_secret = ''

    for frame in frames:
        if frame in ambiguous_frames:
            continue

        basis_orientation = (measurement_basis[frame[0]], measurement_basis[frame[1]])
        measurement_result = BOB_MR_DERIVATION[basis_orientation]
        shared_secret += KEY_DERIVATION[sifting_strings[frame]][measurement_result]

    return shared_secret


io = get_process()

io.recvuntil(b'{"double_matchings": ')
data = json.loads('{"double_matchings": ' + io.recvline().decode())
io.recvline()

double_matchings = data.get('double_matchings', [])
frames = list(map(tuple, data.get('frames', [])))
sifting_strings = data.get('sifting_strings', [])
ambiguous_frames = set(map(tuple, data.get('ambiguous_frames', [])))

bob_sifting_strings = dict(zip(frames, sifting_strings))

used = sorted(set(frames).difference(ambiguous_frames))

non_ambiguous = {t: s for t, s in bob_sifting_strings.items() if s[:2] in {'00', '11'}}
used_non_ambiguous = {t: s for t, s in non_ambiguous.items() if t in used}

basis = {used[0][0]: 'Z'}

while len(basis) < len(used):
    old_basis = basis.copy()

    for u, m in old_basis.items():
        for t, v in used_non_ambiguous.items():
            if u == t[0] and v == '11,11' and t[1] not in basis:
                basis[t[1]] = 'Z' if m == 'X' else 'X'
            elif u == t[1] and v == '11,11' and t[0] not in basis:
                basis[t[0]] = 'Z' if m == 'X' else 'X'
            elif u == t[0] and v == '00,11' and t[1] not in basis:
                basis[t[1]] = m
            elif u == t[1] and v == '00,11' and t[0] not in basis:
                basis[t[0]] = m

    if len(old_basis) == len(basis):
        break

shared_key = generate_shared_key(basis, frames, ambiguous_frames, bob_sifting_strings)
io.success(f'Shared key: {shared_key}')

key = hashlib.sha256(shared_key.encode()).digest()
cipher = AES.new(key, AES.MODE_ECB)
command = cipher.encrypt(pad(b'OPEN THE GATE', AES.block_size))
io.sendlineafter(b'> ', json.dumps({'command': command.hex()}).encode())

try:
    data = json.loads(io.recvline().decode())
    flag = 'HTB' + data.get('info', '').split('HTB')[1]
    io.success(flag)
except (EOFError, json.decoder.JSONDecodeError):
    io.failure('Please, try again')
