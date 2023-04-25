import re

from Crypto.Util.number import long_to_bytes
from hashlib import sha512


def repeating_xor_key(message: bytes, key: bytes) -> bytes:
    repeation = 1 + (len(message) // len(key))
    key = key * repeation
    key = key[:len(message)]

    msg = bytes([c ^ k for c, k in zip(message, key)])
    return msg


def h(m: str) -> int:
    return int(sha512(m.encode()).hexdigest(), 16)


def get_number(pattern: str, res: str) -> int:
    return int(re.findall(pattern, res)[0])


def main():
    with open('output.txt') as o:
        res = o.read()

    q = get_number(r'\[\+\] q condition is satisfied : 256 bit\n(\d+)', res)
    p = get_number(r'\[\+\] p condition is satisfied : 2048 bit\n(\d+)', res)
    g = get_number(r'\[\+\] g condition is satisfied \n(\d+)', res)
    y = get_number(r'\[\+\] public key  : (\d+)', res)

    m_i = re.findall(r'message : (.+)', res)
    signatures = re.findall(r'signature: \((\d+?), (\d+?)\)', res)
    signatures = list(map(lambda s: list(map(int, s)), signatures))

    r_i = list(map(lambda rs: rs[0], signatures))
    s_i = list(map(lambda rs: rs[1], signatures))

    ctf = re.findall(r'\[\+\] Cipher Text Flag \(CTF\) : \n(.+)', res)[0]
    ctf = bytes.fromhex(ctf)

    print(f'{len(r_i) = }, {len(set(r_i)) = }')
    same_k = (-1, -1)

    for i, r in enumerate(r_i):
        if r in r_i[i + 1:]:
            same_k = (i, r_i.index(r, i + 1))
            break

    print(f'{same_k = }')

    m29, r, s29 = m_i[same_k[0]], r_i[same_k[0]], s_i[same_k[0]]
    m74, r, s74 = m_i[same_k[1]], r_i[same_k[1]], s_i[same_k[1]]

    k_inv = (s29 - s74) * pow(h(m29) - h(m74), -1, q) % q
    k = pow(k_inv, -1, q)
    x = (s29 * k - h(m29)) * pow(r, -1, q) % q

    print(f'{x = }')

    key = long_to_bytes(x)
    flag = repeating_xor_key(ctf, key)

    print()
    print(flag.decode())


if __name__ == '__main__':
    main()
