#!/usr/bin/env python3

import sys

from typing import Dict, List

sys.setrecursionlimit(100000)

enc_data: List[str]
freqs: Dict[str, float]

with open('output.txt') as o, open('frequencies.txt') as f:
    enc_data = o.read().splitlines()
    freqs = eval(f.read())

alphabet = set(enc_data)

enc_freqs = {enc: enc_data.count(enc) for enc in enc_data}
new_freqs = {b: round(f * len(enc_data)) for b, f in freqs.items() if f != 0}

done = False


def dfs(bigram: str, index: int = 0, bigrams: List[str] | None = None):
    global done

    bigrams = [] if bigrams is None else bigrams

    if index == len(enc_data) == len(bigrams):
        print(''.join(map(lambda s: s[0], bigrams[1:])) + bigram)
        done = True

    if done:
        return

    count = enc_freqs[enc_data[index]]
    bigrams.append(bigram)

    for next_bigram in next_bigrams(bigram[-1], count):
        dfs(next_bigram, index + 1, bigrams.copy())


def next_bigrams(letter: str, count: int) -> List[str]:
    return [b for b, n in new_freqs.items() if n == count and b.startswith(letter)]


dfs('*A')
