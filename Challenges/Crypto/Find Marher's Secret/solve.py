#!/usr/bin/env python3

import json

from pwn import log, remote, sys


def get_process():
    if len(sys.argv) == 2:
        host, port = sys.argv[1].split(':')

    return remote(host, int(port))


def iv_to_hex(iv):
    return ''.join(map(lambda n: f'{n:02x}', iv))


plain_snap = 'aa'
key_length = 27
N = 256


def main():
    p = get_process()

    rows = []
    progress = log.progress('A')

    for A in range(key_length):
        progress.status(str(A))

        for V in range(N):
            iv = [A + 3, N - 1, V]

            payload = json.dumps({
                'option': 'encrypt',
                'iv': iv_to_hex(iv),
                'pt': plain_snap,
            })

            p.sendlineafter(b'> ', payload.encode())
            ct = int(json.loads(p.recvline().decode())['ct'], 16)
            rows.append([iv[0], iv[1], iv[2], ct])

    progress.success(str(A))

    key = [0] * (3 + key_length)

    for A in range(key_length):
        prob = [0] * N

        for row in rows:
            key[0], key[1], key[2] = row[:3]

            j = 0
            box = list(range(N))

            for i in range(A + 3):
                j = (j + box[i] + key[i]) % N
                box[i], box[j] = box[j], box[i]

                if i == 1:
                    first, second = box[0], box[1]

            i = A + 3
            z = box[1]

            if z + box[z] == A + 3:
                if first != box[0] or second != box[1]:
                    continue

                key_stream_byte = row[3] ^ int(plain_snap, 16)
                key_byte = (key_stream_byte - j - box[i]) % N
                prob[key_byte] += 1

        key[A + 3] = prob.index(max(prob))

    secret_key = bytes(key[3:])
    log.success(f'Key: {secret_key.hex()}')

    payload = json.dumps({
        'option': 'claim',
        'key': secret_key.hex(),
    })

    p.sendlineafter(b'> ', payload.encode())
    log.success('Flag: ' + json.loads(p.recvline().decode())['flag'])
    p.close()


if __name__ == '__main__':
    main()
