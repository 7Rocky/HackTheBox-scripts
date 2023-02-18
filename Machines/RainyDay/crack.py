#!/usr/bin/env python3

import bcrypt
import sys


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


if __name__ == '__main__':
    main()
