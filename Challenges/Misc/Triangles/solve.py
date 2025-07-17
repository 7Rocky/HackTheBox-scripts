#!/usr/bin/env python3

import csv

from collections import defaultdict
from itertools import product


with open('grid.csv') as f_grid, open('out.csv') as f_out:
    grid = [row for row in csv.reader(f_grid)]
    results = f_out.read().splitlines()

values = defaultdict(list)

for x, row in enumerate(grid):
    for y, value in enumerate(row):
        values[value].append(x + 1j * y)

for i in range(0, len(results), 6):
    val1, d1 = results[i + 0][:1], float(results[i + 0][2:])
    val2, d2 = results[i + 1][:1], float(results[i + 1][2:])
    val3, d3 = results[i + 2][:1], float(results[i + 2][2:])

    d12 = float(results[i + 3][3:])
    d23 = float(results[i + 4][3:])
    d31 = float(results[i + 5][3:])

    for P1, P2, P3 in product(values[val1], values[val2], values[val3]):
        if abs(P1 - P2) == d12 and abs(P2 - P3) == d23 and abs(P3 - P1) == d31:
            break

    for value, points in values.items():
        for F in points:
            if abs(F - P1) == d1 and abs(F - P2) == d2 and abs(F - P3) == d3:
                print(value, end='')
                break
