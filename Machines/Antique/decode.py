import binascii
import sys


def main():
    bits = sys.argv[1:]

    try:
        print(''.join(map(lambda x: x.decode(), map(binascii.unhexlify, bits))))
    except binascii.Error as e:
        print('binascii.Error', e)


if __name__ == '__main__':
    main()
