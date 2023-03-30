#!/usr/bin/env python3

def main():
    with open('output.txt') as f:
        N = int(f.readline())
        remainder = int(f.readline())
        a, b, c = eval(f.readline())

    m1 = pow(2 * remainder, -1, N) * (c - a - remainder ** 2) % N
    m = m1 + m1 + remainder

    print(bytes.fromhex(hex(m)[2:]).decode())


if __name__ == '__main__':
    main()
