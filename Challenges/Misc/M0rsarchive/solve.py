#!/usr/bin/env python3

import cv2

from pwn import log, os


morse_alphabet = {
    '.-': 'A',
    '-...': 'B',
    '-.-.': 'C',
    '-..': 'D',
    '.': 'E',
    '..-.': 'F',
    '--.': 'G',
    '....': 'H',
    '..': 'I',
    '.---': 'J',
    '-.-': 'K',
    '.-..': 'L',
    '--': 'M',
    '-.': 'N',
    '---': 'O',
    '.--.': 'P',
    '--.-': 'Q',
    '.-.': 'R',
    '...': 'S',
    '-': 'T',
    '..-': 'U',
    '...-': 'V',
    '.--': 'W',
    '-..-': 'X',
    '-.--': 'Y',
    '--..': 'Z',
    '/': ' ',
    '.----': '1',
    '..---': '2',
    '...--': '3',
    '....-': '4',
    '.....': '5',
    '-....': '6',
    '--...': '7',
    '---..': '8',
    '----.': '9',
    '-----': '0',
    '.-.-.-': '.',
    '--..--': ',',
    '---...': ':',
    '..--..': '?',
    '.----.': "'",
    '-....-': '-',
    '-..-.': '/',
    '.--.-.': '@',
    '-...-': '=',
}


def translate_to_morse(number: int) -> str:
    dictionary = {1: '.', 3: '-'}
    return dictionary.get(number, '')


def next_image(path: str) -> str:
    img = cv2.imread(path)
    dummy_pixel = img[0][0]

    morse_code = []

    for row in img:
        morse_row_code = [0]

        for pixel in row:
            if (pixel == dummy_pixel).all():
                if morse_row_code[-1] != 0:
                    morse_row_code.append(0)
            else:
                morse_row_code[-1] += 1

        morse_row_code = [code for code in morse_row_code if code != 0]

        if len(morse_row_code):
            morse_code.append(''.join(map(translate_to_morse, morse_row_code)))

    return ''.join(morse_alphabet.get(code, '') for code in morse_code).lower()


def main():
    path = './'
    prog = log.progress('Depth')

    for i in range(999, -1, -1):
        prog.status(str(i))
        password = next_image(f'{path}pwd.png')
        os.system(f'unzip -P {password} -d flag{i} {path}flag_{i}.zip &>/dev/null')
        path = f'flag{i}/flag/'

    prog.success(str(i))

    with open(f'{path}flag') as f:
        log.success(f.read().strip())

    os.system('rm -r flag[0-9]*')


if __name__ == '__main__':
    main()
