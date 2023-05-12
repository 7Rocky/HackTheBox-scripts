#!/usr/bin env python3

from pwn import log, remote, sys, xor

fib = [1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 121, 98, 219, 61]


def main():
    host, port = sys.argv[1].split(':')
    io = remote(host, port)

    io.sendlineafter(b'Your option: ', b'0')
    io.recvuntil(b'encrypted_flag: ')
    encrypted_flag = bytes.fromhex(io.recvline().strip().decode())
    io.recvuntil(b'a: ')
    flag_a = bytes.fromhex(io.recvline().strip().decode())
    io.recvuntil(b'b: ')
    flag_b = bytes.fromhex(io.recvline().strip().decode())

    secret_a = b'HTB{th3_s3crt_A}'

    flag_prog = log.progress('Flag')
    poa = log.progress('Bytes')

    def decrypt_block(ct_block):
        dec = []
        poa.status('0 / 16')

        for i in range(16):
            for b_byte in range(256):
                io.sendlineafter(b'Your option: ', b'1')
                io.sendlineafter(b'Enter your ciphertext in hex: ', ct_block.hex().encode())
                b = bytes([0] * (15 - i) + [b_byte]) + xor(bytes(dec), bytes(fib[1: len(dec) + 1]))

                io.sendlineafter(b'Enter the B used during encryption in hex: ', b.hex().encode())

                if io.recvline() == b'Message successfully sent!\n':
                    poa.status(f'{i + 1} / 16')
                    dec = [b_byte ^ fib[0]] + dec
                    break

        return dec

    encrypted_flag_blocks = [encrypted_flag[i:i+16] for i in range(0, len(encrypted_flag), 16)]

    flag = b''
    a, b = flag_a, flag_b

    for block in encrypted_flag_blocks:
        ct_block = xor(block, secret_a, a)
        dec = decrypt_block(ct_block)
        flag += xor(dec, b)

        if b'\x01' not in flag:
            flag_prog.status(flag.decode())

        a, b = flag[-16:], block

    if b'\x01' in flag:
        flag = flag[:flag.index(b'\x01')]

    flag_prog.success(flag.decode())
    poa.success()


if __name__ == '__main__':
    main()
