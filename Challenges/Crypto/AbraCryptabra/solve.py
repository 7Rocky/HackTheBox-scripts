#!/usr/bin/env python3

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from hashlib import md5
from pwn import log, remote, sys
from sage.all import matrix, QQ, ZZ
from typing import List


def get_process():
    if len(sys.argv) != 2:
        log.warning(f'Usage: python3 {sys.argv[0]} <host:port>')
        exit(1)

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def do_round(io, guess=1337):
    io.sendlineafter(b'> ', str(guess).encode())
    io.recvline()

    if (r := io.recvline().decode()) != '\n':
        return int(r)


def hidden_number_problem(a, b, m, X):
    assert len(a) == len(b)

    n1 = len(a)
    n2 = len(a[0])
    B = matrix(QQ, n1 + n2 + 1, n1 + n2 + 1)

    for i in range(n1):
        for j in range(n2):
            B[n1 + j, i] = a[i][j]

        B[i, i] = m
        B[n1 + n2, i] = b[i] - X // 2

    for j in range(n2):
        B[n1 + j, n1 + j] = X / QQ(m)

    B[n1 + n2, n1 + n2] = X

    B = B.LLL()

    for v in B.rows():
        xs = [int(v[i] + X // 2) for i in range(n1)]
        ys = [(int(v[n1 + j] * m) // X) % m for j in range(n2)]

        if all(y != 0 for y in ys) and v[n1 + n2] == X:
            return xs, ys


def crack_tlcg(y, k, s, m, a):
    a_ = []
    b_ = []
    X = 2 ** (k - s)
    mult1 = a
    mult2 = 1

    for i in range(len(y)):
        a_.append([mult1, mult2])
        b_.append(- X * y[i])
        mult1 = (a * mult1) % m
        mult2 = (a * mult2 + 1) % m

    _, (x0_, c_) = hidden_number_problem(a_, b_, m, X)
    return m, a, c_, x0_


class LCG:
    def __init__(self, m, a, s, c, s0):
        self.m = m
        self.a = a
        self.s = s
        self.c = c
        self.k = int(m).bit_length()
        self.state = s0

    def next(self):
        self.state = (self.a * self.state + self.c) % self.m
        return self.state >> (self.k - self.s)


def knapsack(a_i: List[int], b: int) -> int:
    M = matrix(ZZ, len(a_i) + 1, len(a_i) + 1)

    for i, a in enumerate(a_i):
        M[i, i] = 1
        M[i, -1] = a

    M[-1, -1] = -b
    B = M.LLL()

    for u_i in B.rows():
        if all(u in {0, 1} for u in u_i[:-1]) and b == sum(a * u for a, u in zip(a_i, u_i)):
            return u_i[:-1]


def bin2dec(b: List[int]) -> int:
    return int(''.join(map(str, b)), 2)


def main():
    io = get_process()
    M, a = 108314726549199134030277012155370097074, 31157724864730593494380966212158801467
    k = int(M).bit_length()
    s = 32

    Y = [do_round(io) for _ in range(10)]

    _, _, c, s0 = crack_tlcg(Y, k, s, M, a)

    lcg = LCG(M, a, s, c, s0)

    try:
        for y in Y:
            assert y == lcg.next()
    except AssertionError:
        log.warning('LCG failed. Trying again...')
        io.close()
        main()

    log.success('LCG cracked')
    player_health, wizard_health = 90, 200

    prog = log.progress('Health')

    while wizard_health:
        prog.status(f'Player: {player_health} | Wizard {wizard_health}')

        if do_round(io, lcg.next()) is None:
            wizard_health -= 1
        else:
            player_health -= 1

    prog.success(f'Player: {player_health} | Wizard {wizard_health}')

    length = int(io.recvline().decode())
    log.info(f'Flag length: {length // 8}')
    public_key = []

    for i in range(length):
        if i % 8:
            public_key.append(int(io.recvline().decode()))
        else:
            io.recvline()

    enc_message = bytes.fromhex(io.recvline().decode())
    io.close()

    for _ in range(player_health - 1):
        lcg.next()

    key = md5(str(lcg.next()).encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC)

    try:
        message = unpad(cipher.decrypt(enc_message), AES.block_size)
    except ValueError:
        log.warning('Padding error. Trying again...')
        main()

    log.info(f'Encrypted message: {message}')

    enc_flag = int(message.split(b'Harry, ')[1].decode(), 16)

    if (r := knapsack(public_key, enc_flag)):
        flag = [bin2dec([0, *r[i: i + 7]]) for i in range(0, len(r), 7)]
        log.success('HTB{' + ''.join(map(chr, flag)) + '}')
    else:
        log.warning('Knapsack failed. Trying again...')
        main()

    exit(0)


if __name__ == '__main__':
    main()
