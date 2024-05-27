#!/usr/bin/env python3

from pwn import process, remote, sys


pieces = {
    u'\u2654': 'K',
    u'\u2655': 'Q',
    u'\u2656': 'R',
    u'\u2657': 'B',
    u'\u2658': 'N',
    u'\u2659': 'P',
    u'\u265A': 'k',
    u'\u265B': 'q',
    u'\u265C': 'r',
    u'\u265D': 'b',
    u'\u265E': 'n',
    u'\u265F': 'p',
}

host, port = sys.argv[1].split(':')
io = remote(host, port)


def board_to_fen() -> str:
    fen = ''
    io.recvuntil(b'\x1b[')
    io.recvline()

    for _ in range(8):
        empty = 0

        for data in io.recvline().strip().split(b'\x1b[')[2:-2]:
            piece = data[data.index(b'm') + 1:]

            if piece == b'  ':
                empty += 1
            elif piece.decode() in pieces:
                fen += str(empty or '') + pieces[piece.decode()]
                empty = 0

        fen += str(empty or '') + '/'

    io.recvline()
    return fen[:-1] + ' w - - 0 1'


stockfish = process('./stockfish/stockfish-ubuntu-x86-64')
stockfish.recv()


def get_bestmove(fen: str):
    stockfish.sendline(f'position fen {fen}\ngo depth 20'.encode())
    stockfish.recvuntil(b'bestmove ')
    return stockfish.recvline().decode().split(' ')[0]


round_prog = io.progress('Round')

for r in range(25):
    round_prog.status(f'{r + 1} / 25')
    fen = board_to_fen()
    bestmove = get_bestmove(fen)
    io.sendlineafter(b"What's the best move?\n", bestmove.encode())
    io.recvline()

round_prog.success('25 / 25')
io.success(io.recvline().decode())
