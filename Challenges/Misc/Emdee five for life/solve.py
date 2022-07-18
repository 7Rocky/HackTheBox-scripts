#!/usr/bin/env python3

import hashlib
import re
import requests
import sys


def main():
    if len(sys.argv) == 1:
        print('Usage: python3', sys.argv[0], '<ip:port>')
        exit(1)

    url = f'http://{sys.argv[1]}'
    s = requests.session()

    r = s.get(url)

    md5 = hashlib.md5(r.content[167:187]).hexdigest()
    r = s.post(url, data={'hash': md5})

    print(re.findall(r'HTB\{.*?\}', r.text)[0])


if __name__ == '__main__':
    main()
