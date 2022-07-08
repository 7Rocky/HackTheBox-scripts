#!/usr/bin/env python3

import re


def derive_key(key):
    derived_key = []

    for i, char in enumerate(key):
        previous_letters = key[:i]
        new_number = 1

        for j, previous_char in enumerate(previous_letters):
            if previous_char > char:
                derived_key[j] += 1
            else:
                new_number += 1

        derived_key.append(new_number)

    return derived_key


def transpose(array):
    return [row for row in map(list, zip(*array))]


def flatten(array):
    return "".join([i for sub in array for i in sub])


def twisted_columnar_decrypt(ct, key):
    derived_key = derive_key(key)
    width = len(key)
    length = len(ct) // len(key)

    blocks = [list(ct[i:i + length]) for i in range(0, len(ct), length)]

    pt = blocks.copy()

    for i in range(width):
        pt[derived_key.index(i + 1)] = blocks[i][::-1]

    pt = transpose(pt)
    pt = flatten(pt)

    return pt


def main():
    with open('encrypted_messages.txt') as f:
        enc_messages = [line.strip() for line in f.readlines()]

    with open('dialog.txt') as f:
        key = re.findall(r'The key is: (\d*)', f.read())[0]

    messages = []

    for enc_message in enc_messages:
        messages.append(twisted_columnar_decrypt(enc_message, key))

    print('\n'.join(messages))


if __name__ == '__main__':
    main()
