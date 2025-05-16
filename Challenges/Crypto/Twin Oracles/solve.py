#!/usr/bin/env python3

from pwn import process, remote, sys

from Crypto.Util.number import isPrime, long_to_bytes

from server import ChaosRelic


def get_process():
    if len(sys.argv) == 1:
        return process(['python3', 'server.py'])
    
    host, port = sys.argv[1].split(':')
    return remote(host, port)


def query(x: int) -> int:
    io.sendlineafter(b'> ', b'2')
    io.sendlineafter(b"Submit your encrypted scripture for the Seers' judgement: ", hex(x).encode())
    io.recvuntil(b'The Seers whisper their answer: ')
    return int(io.recvline().decode())


io = get_process()

io.recvuntil(b"The Ancient Chaos Relic fuels the Seers' wisdom. Behold its power: M = ")
M = int(io.recvline().decode())

io.sendlineafter(b'> ', b'1')
io.recvuntil(b'The Elders grant you insight: n = ')
n = int(io.recvline().decode())
io.recvuntil(b'The ancient script has been sealed: ')
c = int(io.recvline().decode())

results = []
queries = 0

queries_prog = io.progress('Queries')

primes_15 = {x for x in range(2 ** 14, 2 ** 15) if isPrime(x)}

while len(primes_15) != 1:
    queries += 1
    queries_prog.status(f'{queries} / 1500')
    res = 1 - query(1)

    for t in list(primes_15):
        if res != pow(t, 2 ** queries, M) % 2:
            primes_15.remove(t)

    results.append(res)

x0 = list(primes_15)[0]
io.info(f'{x0 = }')

my_relic = ChaosRelic()
my_relic.M = M
my_relic.x = x0

for r in results:
    assert r == my_relic.get_bit()

lb, ub = 0, n

e = 65537
b = 1

flag_prog = io.progress('Flag')

while lb < ub:
    queries += 1
    flag_prog.status(str(long_to_bytes(lb)))
    queries_prog.status(f'{queries} / 1500')
    bit = my_relic.get_bit()

    if bit == 0:
        x = (pow(2 ** b, e, n) * c) % n
    else:
        x = (pow(2 ** (b - 1), e, n) * c) % n

    if query(x) == 0:
        ub = (ub + lb) // 2
    else:
        lb = (ub + lb) // 2

    b += 1

flag_prog.success(str(long_to_bytes(lb)))

while c != pow(lb, e, n):
    lb += 1

io.success(f'Flag: {long_to_bytes(lb).decode()}')
