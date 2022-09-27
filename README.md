# Hack The Box scripts

This repository is made to upload some custom interesting scripts in different programming languages that are useful to exploit certain vulnerabilities in Hack The Box retired machines/challenges.

Detailed write-ups are posted on my personal blog: https://7rocky.github.io/en/htb and https://7rocky.github.io/en/ctf/htb-challenges.

For every machine/challenge, there is a `README.md` file that explains how the script is built, giving some reasons why and doing some troubleshooting if necessary.

The aim of this repository is to provide useful scripts that can be adapted to other circumstances and show how some techniques can be performed using a certain programming language.

Hope it is useful! :smile:

| Machine                               | Scripts / Programs                                                                                                                                                                                                                                                                          | Language                                       | Purpose                                                                                                                                                                                                                                                                                         |
| ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------| ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [Altered](Machines/Altered)           | [bf_pin.rb](Machines/Altered/bf_pin.rb)                                                                                                                                                                                                                                                     | Ruby                                           | Brute Force attack on a 4-digit PIN                                                                                                                                                                                                                                                             |
| [Antique](Machines/Antique)           | [decode.py](Machines/Antique/decode.py)                                                                                                                                                                                                                                                     | Python                                         | Decoding a password from SNMP                                                                                                                                                                                                                                                                   |
| [Backdoor](Machines/Backdoor)         | [dpt.py](Machines/Backdoor/dpt.py)<br>[pwn_gdbserver.py](Machines/Backdoor/pwn_gdbserver.py)                                                                                                                                                                                                | Python<br>Python                               | Read files using Diretory Path Traversal<br>Obtain a reverse shell via GNU gdbserver                                                                                                                                                                                                            |
| [BountyHunter](Machines/BountyHunter) | [xxe.sh](Machines/BountyHunter/xxe.sh)                                                                                                                                                                                                                                                      | Bash                                           | Read files using an XXE attack                                                                                                                                                                                                                                                                  |
| [Forge](Machines/Forge)               | [ssrf.py](Machines/Forge/ssrf.py)                                                                                                                                                                                                                                                           | Python                                         | Automate a SSRF explotation through an URL                                                                                                                                                                                                                                                      |
| [GoodGames](Machines/GoodGames)       | [autopwn.py](Machines/GoodGames/autopwn.py)                                                                                                                                                                                                                                                 | Python                                         | Compromise the machine from scratch to `root`                                                                                                                                                                                                                                                   |
| [Hancliffe](Machines/Hancliffe)       | [decrypt.sh](Machines/Hancliffe/decrypt.sh)<br>[encrypt1.c](Machines/Hancliffe/encrypt1.c)<br>[encrypt2.c](Machines/Hancliffe/encrypt2.c)<br>[exploit.py](Machines/Hancliffe/exploit.py)                                                                                                    | <br>Bash<br>C<br>C<br>Python                   | Decrypt password using brute force<br>ROT47 cipher<br>Atbash cipher<br>Stack-based Buffer Overflow exploit using Socket Reuse                                                                                                                                                                   |
| [Horizontall](Machines/Horizontall)   | [rce_strapy.py](Machines/Horizontall/rce_strapy.py)                                                                                                                                                                                                                                         | Python                                         | Chain two exploits for Strapi to obtain a reverse shell                                                                                                                                                                                                                                         |
| [Intelligence](Machines/Intelligence) | [reqPdf.go](Machines/Intelligence/reqPdf.go)                                                                                                                                                                                                                                                | Go                                             | Fuzz for PDF files with a guessable filename                                                                                                                                                                                                                                                    |
| [Monitors](Machines/Monitors)         | [deserialization.sh](Machines/Monitors/deserialization.sh)                                                                                                                                                                                                                                  | Bash                                           | Automate the process to exploit a deserialization attack in Java                                                                                                                                                                                                                                |
| [NodeBlog](Machines/NodeBlog)         | [nosqli.sh](Machines/NodeBlog/nosqli.sh)<br>[xxe.py](Machines/NodeBlog/xxe.py)<br>[unserialize_rce.js](Machines/NodeBlog/unserialize_rce.js)                                                                                                                                                | Bash<br>Python<br>Node.js                      | Extract password using RegEx in a NoSQL injection<br>Read files using an XXE attack<br>Obtain a reverse shell exploiting an insecure deserialization vulnerability                                                                                                                              |
| [OverGraph](Machines/OverGraph)       | [get_admin_token.py](Machines/OverGraph/get_admin_token.py)<br>[extract_id_rsa.py](Machines/OverGraph/extract_id_rsa.py)<br>[bf_token.py](Machines/OverGraph/bf_token.py)<br>[exploit_rce.py](Machines/OverGraph/exploit_rce.py)<br>[exploit_write.py](Machines/OverGraph/exploit_write.py) | Python<br>Python<br>Python<br>Python<br>Python | Obtain `adminToken` chaining CSRF through Open Redirect and AngularJS XSS to access `localStorage`<br>Read `id_rsa` exploiting `ffmpeg` SSRF<br>Brute force attack to obtain a valid token<br>Binary exploit to obtain RCE as `root`<br>Binary exploit to obtain write permissions as `root`    |
| [Pikaboo](Machines/Pikaboo)           | [autopwn.py](Machines/Pikaboo/autopwn.py)                                                                                                                                                                                                                                                   | Python                                         | Compromise the machine from scratch to `root`                                                                                                                                                                                                                                                   |
| [Previse](Machines/Previse)           | [foothold.go](Machines/Previse/foothold.go)                                                                                                                                                                                                                                                 | Go                                             | Register a new account and obtain a reverse shell exploiting a command injection                                                                                                                                                                                                                |
| [Retired](Machines/Retired)           | [first_exploit.py](Machines/Retired/first_exploit.py)<br>[second_exploit.py](Machines/Retired/second_exploit.py)<br>[third_exploit.py](Machines/Retired/third_exploit.py)                                                                                                                   | Python<br>Python<br>Python                     | Buffer Overflow. PIE and ASLR bypass. NX bypass (ROP). Ret2Libc with custom command. Brute force<br>Buffer Overflow. PIE and ASLR bypass. NX bypass (ROP). Ret2Libc with custom command. Write-what-where primitive<br>Buffer Overflow. PIE and ASLR bypass. NX bypass (mprotect and shellcode) |
| [Rope](Machines/Rope)                 | [fmtstr_exploit.py](Machines/Rope/fmtstr_exploit.py)<br>[root_exploit.py](Machines/Rope/root_exploit.py)                                                                                                                                                                                    | Python<br>Python                               | Format String exploitation<br>Buffer Overflow. PIE and Canary bypass (brute force). NX bypass (ROP). ASLR bypass (leaks). Ret2Libc through socket                                                                                                                                               |
| [Scanned](Machines/Scanned)           | [exploit.sh](Machines/Scanned/exploit.sh)<br>[crack.go](Machines/Scanned/crack.go)                                                                                                                                                                                                          | Bash<br>Go                                     | Read files uand list directories by uploading a custom binary that escapes from a sandbox environment<br>Crack Django salted MD5 hash                                                                                                                                                           |
| [Spider](Machines/Spider)             | [ssti.py](Machines/Spider/ssti.py)<br>[xxe.sh](Machines/Spider/xxe.sh)                                                                                                                                                                                                                      | Python<br>Bash                                 | Performing an SSTI on Jinja2<br>Read files as `root` using an XXE attack                                                                                                                                                                                                                        |
| [Static](Machines/Static)             | [get_vpn.rb](Machines/Static/get_vpn.rb)<br>[xdebug_shell.py](Machines/Static/xdebug_shell.py)<br>[exploit.py](Machines/Static/exploit.py)                                                                                                                                                  | Ruby<br>Python<br>Python                       | Downloading a VPN handling a TOTP and a Gzip file patch<br>Obtain a reverse shell for xdebug in a PHP server<br>Binary exploitation using a Format Strings vulnerability                                                                                                                        |
| [Timing](Machines/Timing)             | [upload.py](Machines/Timing/upload.py)                                                                                                                                                                                                                                                      | Python                                         | Manage to upload a PHP web shell and provide the URL to access it                                                                                                                                                                                                                               |
| [Unicode](Machines/Unicode)           | [dpt-jwks.py](Machines/Unicode/dpt-jwks.py)                                                                                                                                                                                                                                                 | Python                                         | Interactive prompt to read files from the server via Directory Path Traversal and serve a JWKS to interact with the website as `admin`                                                                                                                                                          |
| [Union](Machines/Union)               | [UnionSQLi.java](Machines/Union/UnionSQLi.java)                                                                                                                                                                                                                                             | Java                                           | Interactive prompt to make SQL queries using a Union-based SQLi                                                                                                                                                                                                                                 |
| [Writer](Machines/Writer)             | [sqli.py](Machines/Writer/sqli.py)<br>[foothold.py](Machines/Writer/foothold.py)                                                                                                                                                                                                            | Python<br>Python                               | Dump database contents and read files using a Boolean-based SQLi<br>Obtain a reverse shell using a command injection via file upload                                                                                                                                                            |

| Challenge                                                                                   | Scripts / Programs                                                                                                               | Language         | Purpose                                                         |
| ------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------- | ---------------- | --------------------------------------------------------------- |
| [Crypto/Android-in-the-Middle](Challenges/Crypto/Android-in-the-Middle)                     | [solve.py](Challenges/Crypto/Android-in-the-Middle/solve.py)                                                                     | Python           | Diffie-Hellman. MITM                                            |
| [Crypto/Down the Rabinhole](Challenges/Crypto/Down%20the%20Rabinhole)                       | [solve.py](Challenges/Crypto/Down%20the%20Rabinhole/solve.py)                                                                    | Python           | GCD. Modular arithmetic. Padding                                |
| [Crypto/How The Columns Have Turned](Challenges/Crypto/How%20The%20Columns%20Have%20Turned) | [solve.py](Challenges/Crypto/How%20The%20Columns%20Have%20Turned/solve.py)                                                       | Python           | Reverse encryption algorithm                                    |
| [Crypto/Jenny From The Block](Challenges/Crypto/Jenny%20From%20The%20Block)                 | [solve.py](Challenges/Crypto/Jenny%20From%20The%20Block/solve.py)                                                                | Python           | Block cipher. SHA256                                            |
| [Crypto/One Step Closer](Challenges/Crypto/One%20Step%20Closer)                             | [solve.sage](Challenges/Crypto/One%20Step%20Closer/solve.sage)                                                                   | SageMath         | RSA. Franklin-Reiter related-message attack                     |
| [Misc/Emdee five for life](Challenges/Misc/Emdee%20five%20for%20life)                       | [solve.py](Challenges/Misc/Emdee%20five%20for%20life/solve.py)<br>[solve.sh](Challenges/Misc/Emdee%20five%20for%20life/solve.sh) | Python<br>Bash   | Compute and send MD5 hash of a string as quickly as possible    |
| [Misc/Insane Bolt](Challenges/Misc/Insane%20Bolt)                                           | [solve.py](Challenges/Misc/Insane%20Bolt/solve.py)                                                                               | Python           | Depth First Search (DFS)                                        |
| [Pwn/ropme](Challenges/Pwn/ropme)                                                           | [solve.py](Challenges/Pwn/ropme/solve.py)                                                                                        | Python           | Buffer Overflow. NX bypass (ROP). ASLR bypass (leaks). Ret2Libc |
| [Pwn/Space pirate: Going Deeper](Challenges/Pwn/Space%20pirate:%20Going%20Deeper)           | [solve.py](Challenges/Pwn/Space%20pirate:%20Going%20Deeper/solve.py)                                                             | Python           | Buffer Overflow. One byte overflow                              |
| [Pwn/Vault-breaker](Challenges/Pwn/Vault-breaker)                                           | [solve.py](Challenges/Pwn/Vault-breaker/solve.py)                                                                                | Python           | Bug abuse. XOR cipher                                           |
| [Reversing/Rebuilding](Challenges/Reversing/Rebuilding)                                     | [solve.py](Challenges/Reversing/Rebuilding/solve.py)                                                                             | Python           | Automate flag extraction from GDB                               |
| [Web/baby ninja jinja](Challenges/Web/baby%20ninja%20jinja)                                 | [ssti.py](Challenges/Web/baby%20ninja%20jinja/ssti.py)                                                                           | Python           | SSTI. RCE. Limited interactive shell session                    |
