#!/usr/bin/env python3

from math import log2

with open('out.txt') as f:
    out = [tuple(map(int, line.split())) for line in f.read().splitlines()]

xor_key = out[0][0] ^ (1 << 4)
flag = ''

for o1, o2 in out:
    flag += chr((int(log2(o1 ^ xor_key)) << 4) | int(log2(o2 ^ xor_key)))

print('Test:', flag)

flag = ''

for o1, o2 in out:
    xor = o1 ^ o2

    if xor:
        i1 = f'{xor:016b}'[::-1].index('1')
        i2 = 15 - f'{xor:016b}'.index('1')

        option1, option2 = (i1 << 4) | i2, (i2 << 4) | i1

        if not (0x20 <= option2 < 0x7f):
            flag += chr(option1)
        elif not (0x20 <= option1 < 0x7f):
            flag += chr(option2)
        else:
            flag += f' [{chr(option1)}{chr(option2)}] '
    else:
        flag += ' [\x33\x44\x55\x66\x77] '

print('\nPossible:', flag)
