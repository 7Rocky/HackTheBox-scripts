#!/usr/bin/env python3

from pwn import re, xor


def main():
    with open('deterministic.txt') as f:
        unique_lines = sorted(set(f.read().splitlines()))

    states = {}

    for line in unique_lines:
        if re.match(r'\d+ \d+ \d+', line):
            state, value, next_state = map(int, line.split())
            states[state] = (value, next_state)

    values = []

    initial_state, final_state = 69420, 999
    current_state = initial_state

    while current_state != final_state:
        value, next_state = states[current_state]
        values.append(value)
        current_state = next_state

    for n in range(256):
        result = xor(bytes(values), bytes([n]))

        if b'HTB' in result:
            print(result.decode())
            break


if __name__ == '__main__':
    main()
