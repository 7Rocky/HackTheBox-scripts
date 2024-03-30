#!/usr/bin/env python3

import string

from base64 import b64decode
from hashlib import sha256

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


ALPHABET = string.ascii_letters + string.digits + '~!@#$%^&*'


def crack_password(password):
    master_key = 0

    for i, p in enumerate((password)):
        if p in ALPHABET[:len(ALPHABET) // 2]:
            master_key |= 1 << i

    return master_key.to_bytes((7 + len(password)) // 8, 'little')


def main():
    password = 't*!zGnf#LKO~drVQc@n%oFFZyvhvGZq8zbfXKvE1#*R%uh*$M6c$zrxWedrAENFJB7xz0ps4zh94EwZOnVT9&h'
    ciphertext = 'GKLlVVw9uz/QzqKiBPAvdLA+QyRqyctsPJ/tx8Ac2hIUl8/kJaEvHthHUuwFDRCs'
    MASTER_KEY = crack_password(password)
    encryption_key = sha256(MASTER_KEY).digest()
    cipher = AES.new(encryption_key, AES.MODE_ECB)

    print(unpad(cipher.decrypt(b64decode(ciphertext)), AES.block_size).decode())

if __name__ == '__main__':
    main()
