#!/usr/bin/env python3

from pwn import process, remote, sys
from twister import Twister

from sage.all import BooleanPolynomialRing, GF, Sequence, vector


EVEN, ODD, NUMBER = 1, 2, 3

N = 128
M = 30
b = 32
MAGIC = 0xb249b015

target = 10000000000000
rounds = 820

F = GF(2)
P = BooleanPolynomialRing(names=','.join(f'y{i}' for i in range(N * b)))


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'roulette_local.py'])

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def bet(option=ODD, amount=1, number=0):
    io.sendlineafter(b'Option: ', str(option).encode())

    if option == NUMBER:
        io.sendlineafter(b'Pick a number: ', str(number).encode())

    io.sendlineafter(b'Bet: ', str(amount).encode())
    io.recvuntil(b'The wheel stops at ')
    output = int(io.recvline().decode())
    data = io.recvline()

    if b'You have ' not in data:
        return output, target

    coins = int(data.decode().split(' ')[2])
    return output, coins


def bits(n):
    return list(map(F, f'{n:032b}'))[::-1]


def xor(a, b):
    return [a_i + b_i for a_i, b_i in zip(a, b)]


def rol(x, d):
    return x[-d:] + x[:-d]


class VarTwister:
    def __init__(self, state):
        self.index = 0
        assert len(state) == N
        self.STATE = state[:]

    def twist(self):
        for i in range(N):
            self.STATE[i] = xor(self.STATE[i], rol(self.STATE[(i + 1) % N], 3))
            self.STATE[i] = xor(self.STATE[i], rol(
                self.STATE[(i + M) % N], b - 9))
            self.STATE[i] = xor(self.STATE[i], bits(MAGIC))

    def rand(self):
        if self.index >= N:
            self.twist()
            self.index = 0

        y = self.STATE[self.index]
        y = xor(y, rol(y, 7))
        y = xor(y, rol(y, b - 15))
        self.index += 1
        return y[:b]


def main():
    coins = 50
    var_state = []

    for k in range(0, N * b, b):
        var_state.append([P.gens()[i] for i in range(k, k + b)])

    var_twister = VarTwister(var_state)
    outputs = []
    equations = []
    u_values = []

    round_prog = io.progress('Round')
    coins_prog = io.progress('Coins')

    for r in range(rounds):
        round_prog.status(f'{r + 1} / {rounds}')
        coins_prog.status(f'{coins}')
        y = var_twister.rand()

        try:
            output, coins = bet()
        except EOFError:
            coins_prog.failure('0')
            io.warning('Try better luck next time')
            exit()

        outputs.append(output)
        u = bits(output)

        for i in range(5):
            equations.append(y[i])
            u_values.append(u[i])

    round_prog.success(f'{rounds} / {rounds}')

    io.info('Solving matrix equation')
    A, _ = Sequence(equations).coefficient_matrix(sparse=False)
    S = A.solve_right(vector(F, u_values))

    if A * S != vector(F, u_values):
        io.failure('Failed to solve matrix equation')
        exit()

    state = [sum(int(y_i) * 2 ** i for i, y_i in enumerate(S[k:k + b]))
             for k in range(0, N * b, b)]
    io.info('Got possible state bits')

    twister = Twister(state)
    twister.index = 0

    for output in outputs:
        guess = twister.rand() % 32

        if output != guess:
            io.failure('Some known guessed output is wrong')
            exit()

    io.success('Verified all state bits')
    r = 0

    while coins < target:
        guess = twister.rand() % 32
        output, coins = bet(option=NUMBER, amount=coins, number=guess)

        if output != guess:
            io.failure('Some unknown guessed output is wrong')
            exit()

        coins_prog.status(f'{coins}')
        r += 1

    coins_prog.success(f'>= {coins}')
    io.success(f'Winning rounds: {r}')
    io.success(io.recvline().decode())


if __name__ == '__main__':
    io = get_process()
    main()
