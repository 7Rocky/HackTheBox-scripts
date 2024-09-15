#!/usr/bin/env python3

from ast import literal_eval
from hashlib import sha256

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


with open('output.txt') as f:
    all_enc_messages = literal_eval(f.readline())
    ct = bytes.fromhex(f.readline())


def try_decrypt(key, iv, ct):
    try:
        pt = unpad(AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct), AES.block_size)
        return pt
    except ValueError:
        return


key0 = sha256(b'0' * 256).digest()
key1 = sha256(b'1' * 256).digest()

messages = []

for enc_messages in all_enc_messages:
    for iv, enc_message in enc_messages:
        if (message := try_decrypt(key0, bytes.fromhex(iv), bytes.fromhex(enc_message))):
            messages.append(message.decode())
            break
        if (message := try_decrypt(key1, bytes.fromhex(iv), bytes.fromhex(enc_message))):
            messages.append(message.decode())
            break


from re import search

from Crypto.Util.number import long_to_bytes

from sage.all import GF, PolynomialRing


shares = []

for message in messages:
    if (share_match := search(r'Share#\d+?#: \((\d+?), (\d+?)\)', message)):
        shares.append((int(share_match.group(1)), int(share_match.group(2))))

    if (gf_match := search(r'GF\((\d+?)\)', message)):
        Fp = GF(int(gf_match.group(1)))

P = PolynomialRing(Fp, 'x')
polynomial = P.lagrange_polynomial(shares)
key = long_to_bytes(int(polynomial(0)))
assert sha256(key).hexdigest().startswith('709149eb5baf8f8cb617226854a7b4f3')

print(unpad(AES.new(key, AES.MODE_ECB).decrypt(ct), AES.block_size).decode())
