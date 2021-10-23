# Hack The Box. Machines. Antique

Machine write-up: https://7rocky.netlify.app/en/htb/antique

### `decode.py`

This script is made to decode a password obtained using `snmpwalk` as hexadecimal digits:

```console
$ snmpwalk -v2c -c public 10.10.11.107 .1.3.6.1.4.1.11.2.3.9.1.1.13.0

iso.3.6.1.4.1.11.2.3.9.1.1.13.0 = BITS: 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 33 1 3 9 17 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135
```

We import `binascii` library to use `unhexlify` function for decoding. As we don't know if the whole stream of digits will decode correctly, we wrap the decoding process using a `try`-`except` block.

Notice that `unhexlify` returns a `bytes` object, so we need to transforme it to `str` using the `decode` function:

```python
    try:
        print(''.join(map(lambda x: x.decode(), map(binascii.unhexlify, bits))))
    except binascii.Error as e:
        print('binascii.Error', e)
```

The bits will be passed to the program as arguments.

First we find that there are decoding errors:

```console
$ python3 decode.py 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 33 1 3 9 17 22 23 25 26 27 30 31 33 34 35 37 38 39 42 43 49 50 51 54 57 58 61 65 74 75 79 82 83 86 90 91 94 95 98 103 106 111 114 115 119 122 123 126 130 131 134 135
binascii.Error Odd-length string
```

We can remove digits from the end until everything decodes correctly:

```console
$ python3 decode.py 50 40 73 73 77 30 72 64 40 31 32 33 21 21 31 32 33
P@ssw0rd@123!!123
```
