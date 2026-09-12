#!/usr/bin/env python3

from Crypto.Cipher import AES


def main():
    with open('packets.icmp.pcap', 'rb') as f:
        exfils = f.read().split(b'exfil-')

    chunks = []

    for i in range(1, len(exfils)):
        key = int(exfils[i - 1][-4:-2].hex(), 16)
        enum = int(exfils[i - 1][-2:].hex(), 16)
        iv = exfils[i][:16]
        ct = exfils[i][16:256 + 16]
        data = AES.new(b'The Bloodharbor!', AES.MODE_CBC, iv).decrypt(ct)
        chunks.append({
            'data': data,
            'enum': enum,
            'key': key
        })

    chunks.sort(key=lambda chunk: chunk['key'])

    cur_key = 0
    key_chunks = {}

    for chunk in chunks:
        if chunk['key'] != cur_key:
            cur_key = chunk['key']
            key_chunks[cur_key] = []

        key_chunks[cur_key].append(chunk)

    for key in key_chunks:
        key_chunks[key].sort(key=lambda chunk: chunk['enum'], reverse=key % 2)

    img = [chunk['data'] for chunks in key_chunks.values() for chunk in chunks]

    with open('flag.png', 'wb') as f:
        f.write(b''.join(img))


if __name__ == '__main__':
    main()
