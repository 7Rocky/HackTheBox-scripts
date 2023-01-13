#!/usr/bin/env python3

from datetime import datetime
from pwn import log, random, string, sys
from typing import List

start = datetime.now()
sys.set_int_max_str_digits(0)


with open('out.txt') as f:
    encrypted_flag = int(f.readline())
    encrypted_state = eval(f.readline())
    public_key = eval(f.readline())

state_one = [0] * len(encrypted_state[1])
set_encrypted_state = set(encrypted_state[1])
sorted_public_key = sorted(public_key)


def decrypt(r: int, ciphertext: int) -> List[int]:
    plaintext = []

    while ciphertext > 0:
        c = (ciphertext % (r ** 2)) % 256
        plaintext.append(c)
        ciphertext = (ciphertext - c) // pow(r, c)

    return plaintext[::-1]


def encrypt(num: int) -> int:
    result = 0

    for multiplier in public_key[::-1]:
        result += multiplier * (num & 1)
        num >>= 1

    return result


def main():
    count = 0

    for num in range(2 ** 32):
        res = encrypt(num)

        if res in set_encrypted_state:
            index = encrypted_state[1].index(res)
            state_one[index] = num
            count += 1
            log.info(f'{count:>3}. {index = :>3}: {state_one[index] = :>10}')

            if count == len(state_one):
                break

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
