#!/usr/bin/env python3

from collections import Counter
from pwn import log, remote, sys


truth_table = {
    '0000000': '0000',
    '1101001': '0001',
    '0101010': '0010',
    '1000011': '0011',
    '1001100': '0100',
    '0100101': '0101',
    '1100110': '0110',
    '0001111': '0111',
    '1110000': '1000',
    '0011001': '1001',
    '1011010': '1010',
    '0110011': '1011',
    '0111100': '1100',
    '1010101': '1101',
    '0010110': '1110',
    '1111111': '1111',
}

host, port = sys.argv[1].split(':')
io = remote(host, port)


def get_chunks():
    io.recvuntil(b'Captured: ')
    data = io.recvline().strip().decode()
    return [data[i : i + 7] for i in range(0, len(data), 7)]


flag = ''
binary_flag = ''

io.info('Collecting samples...')
samples = [get_chunks() for _ in range(50)]

prog = log.progress('Flag')

while '}' not in flag:
    characters = Counter()

    for chunks in samples:
        chunk = chunks[len(binary_flag) // 4]

        if chunk in truth_table:
            characters[truth_table.get(chunk)] += 1

    if len(characters):
        binary_flag += characters.most_common()[0][0]
    else:
        io.info('Collecting more samples...')
        samples = [get_chunks() for _ in range(50)]

    if len(binary_flag) % 8 == 0:
        flag = bytes.fromhex(hex(int(binary_flag, 2))[2:]).decode()
        prog.status(flag)

prog.success(flag)
