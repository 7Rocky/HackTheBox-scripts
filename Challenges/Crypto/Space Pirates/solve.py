#!/usr/bin/env python3

from hashlib import md5
from random import randbytes, seed

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def main():
    with open('msg.enc') as f:
        share = eval(f.readline().split(': ')[1])
        coefficient = eval(f.readline().split(': ')[1])
        secret_message = bytes.fromhex(f.readline().split(': ')[1].strip())

    p = 92434467187580489687
    k = 10
    n = 18

    coeffs = [0, coefficient]

    def next_coeff(val):
        return int(md5(val.to_bytes(32, byteorder='big')).hexdigest(), 16)

    def calc_coeffs():
        for i in range(2, n + 1):
            coeffs.append(next_coeff(coeffs[i - 1]))

    def calc_y(x):
        y = 0

        for i, coeff in enumerate(coeffs):
            y += coeff * x ** i

        return y % p

    calc_coeffs()
    coeffs = coeffs[:k]

    secret = (share[1] - calc_y(share[0])) % p

    seed(secret)
    key = randbytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    flag = unpad(cipher.decrypt(secret_message), 16)
    print(flag.decode())


if __name__ == '__main__':
    main()
