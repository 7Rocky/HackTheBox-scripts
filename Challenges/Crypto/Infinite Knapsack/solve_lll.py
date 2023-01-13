#!/usr/bin/env python3

from datetime import datetime
from pwn import log, random, string
from sage.all import matrix, ZZ
from typing import List


def decrypt(r: int, ciphertext: int) -> List[int]:
    plaintext = []

    while ciphertext > 0:
        c = (ciphertext % (r ** 2)) % 256
        plaintext.append(c)
        ciphertext = (ciphertext - c) // pow(r, c)

    return plaintext[::-1]


def attack(a_i: List[int], b_i: List[int]) -> List[int]:
    M = matrix(ZZ, len(a_i) + 1, len(a_i) + 1)

    for i, a in enumerate(a_i):
        M[i, i] = 1
        M[i, -1] = a

    p_i = []

    prog = log.progress('Index')

    for k, b in enumerate(b_i):
        M[-1, -1] = -b
        prog.status(f'{k + 1} / {len(b_i)}')
        B = M.LLL()

        for u_i in B.rows():
            if b == sum(a * u for a, u in zip(a_i, u_i)):
                p_i.append(bin2dec(u_i[:-1]))
                break

    prog.success(f'{len(b_i)} / {len(b_i)}')

    return p_i


def bin2dec(b: List[int]) -> int:
    return int(''.join(map(str, b)), 2)


def main():
    start = datetime.now()

    with open('out.txt') as f:
        encrypted_flag = int(f.readline())
        encrypted_state = eval(f.readline())
        public_key = eval(f.readline())

    state_one = attack(public_key, encrypted_state[1])
    random.setstate(state=(3, tuple(state_one), None))
    r = random.randint(1, 2 ** 8)
    log.success(f'Random number: {r}')

    shuffled_flag = bytes(decrypt(r, encrypted_flag)).decode()
    log.success(f'Shuffled flag: {shuffled_flag}')

    in_string = string.ascii_letters[:len(shuffled_flag)]
    out_string = ''.join(random.sample(in_string, len(shuffled_flag)))

    flag = [shuffled_flag[out_string.index(c)] for c in in_string]

    log.success('Flag: ' + ''.join(flag))
    log.info(f'Elapsed time: {datetime.now() - start}')


if __name__ == '__main__':
    main()
