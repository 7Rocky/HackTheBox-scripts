# Hack The Box scripts

This repository is made to upload some custom interesting scripts in different programming languages that are useful to exploit certain vulnerabilities in Hack The Box retired machines/challenges.

Detailed write-ups are posted on my personal blog: https://7rocky.github.io/en/htb.

For every machine/challenge, there is a `README.md` file that explains how the script is built, giving some reasons why and doing some troubleshooting if necessary.

The aim of this repository is to provide useful scripts that can be adapted to other circumstances and show how some techniques can be performed using a certain programming language.

Hope it is useful! :smile:

| Machine                               | Scripts / Programs                                                                                                                           | Language                  | Purpose                                                                                                                                                                  |
| ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| [Altered](Machines/Altered)           | [bf_pin.rb](Machines/Altered/bf_pin.rb)                                                                                                      | Ruby                      | Brute Force attack on a 4-digit PIN                                                                                                                                      |
| [Antique](Machines/Antique)           | [decode.py](Machines/Antique/decode.py)                                                                                                      | Python                    | Decoding a password from SNMP                                                                                                                                            |
| [Backdoor](Machines/Backdoor)         | [dpt.py](Machines/Backdoor/dpt.py)<br>[pwn_gdbserver.py](Machines/Backdoor/pwn_gdbserver.py)                                                 | Python<br>Python          | Read files using Diretory Path Traversal<br>Obtain a reverse shell via GNU gdbserver                                                                                     |
| [BountyHunter](Machines/BountyHunter) | [xxe.sh](Machines/BountyHunter/xxe.sh)                                                                                                       | Bash                      | Read files using an XXE attack                                                                                                                                           |
| [Forge](Machines/Forge)               | [ssrf.py](Machines/Forge/ssrf.py)                                                                                                            | Python                    | Automate a SSRF explotation through an URL                                                                                                                               |
| [GoodGames](Machines/GoodGames)       | [autopwn.py](Machines/GoodGames/autopwn.py)                                                                                                  | Python                    | Compromise the machine from scratch to `root`                                                                                                                            |
| [Horizontall](Machines/Horizontall)   | [rce_strapy.py](Machines/Horizontall/rce_strapy.py)                                                                                          | Python                    | Chain two exploits for Strapi to obtain a reverse shell                                                                                                                  |
| [Intelligence](Machines/Intelligence) | [reqPdf.go](Machines/Intelligence/reqPdf.go)                                                                                                 | Go                        | Fuzz for PDF files with a guessable filename                                                                                                                             |
| [Monitors](Machines/Monitors)         | [deserialization.sh](Machines/Monitors/deserialization.sh)                                                                                   | Bash                      | Automate the process to exploit a deserialization attack in Java                                                                                                         |
| [NodeBlog](Machines/NodeBlog)         | [nosqli.sh](Machines/NodeBlog/nosqli.sh)<br>[xxe.py](Machines/NodeBlog/xxe.py)<br>[unserialize_rce.js](Machines/NodeBlog/unserialize_rce.js) | Bash<br>Python<br>Node.js | Extract password using RegEx in a NoSQL injection<br>Read files using an XXE attack<br>Obtain a reverse shell exploiting an insecure deserialization vulnerability       |
| [Pikaboo](Machines/Pikaboo)           | [autopwn.py](Machines/Pikaboo/autopwn.py)                                                                                                    | Python                    | Compromise the machine from scratch to `root`                                                                                                                            |
| [Previse](Machines/Previse)           | [foothold.go](Machines/Previse/foothold.go)                                                                                                  | Go                        | Register a new account and obtain a reverse shell exploiting a command injection                                                                                         |
| [Spider](Machines/Spider)             | [ssti.py](Machines/Spider/ssti.py)<br>[xxe.sh](Machines/Spider/xxe.sh)                                                                       | Python<br>Bash            | Performing an SSTI on Jinja2<br>Read files as `root` using an XXE attack                                                                                                 |
| [Static](Machines/Static)             | [get_vpn.rb](Machines/Static/get_vpn.rb)<br>[xdebug_shell.py](Machines/Static/xdebug_shell.py)<br>[exploit.py](Machines/Static/exploit.py)   | Ruby<br>Python<br>Python  | Downloading a VPN handling a TOTP and a Gzip file patch<br>Obtain a reverse shell for xdebug in a PHP server<br>Binary exploitation using a Format Strings vulnerability |
| [Unicode](Machines/Unicode)           | [dpt-jwks.py](Machines/Unicode/dpt-jwks.py)                                                                                                  | Python                    | Interactive prompt to read files from the server via Directory Path Traversal and serve a JWKS to interact with the website as `admin`                                   |
| [Union](Machines/Union)               | [UnionSQLi.java](Machines/Union/UnionSQLi.java)                                                                                              | Java                      | Interactive prompt to make SQL queries using a Union-based SQLi                                                                                                          |
| [Writer](Machines/Writer)             | [sqli.py](Machines/Writer/sqli.py)<br>[foothold.py](Machines/Writer/foothold.py)                                                             | Python<br>Python          | Dump database contents and read files using a Boolean-based SQLi<br>Obtain a reverse shell using a command injection via file upload                                     |

| Challenge                                               | Scripts / Programs                                 | Language | Purpose                                                         |
| ------------------------------------------------------- | -------------------------------------------------- | -------- | --------------------------------------------------------------- |
| [Pwn/ropme](Challenges/Pwn/ropme)                       | [solve.py](Challenges/Pwn/ropme/solve.py)          | Python   | Buffer Overflow. NX bypass (ROP). ASLR bypass (leaks). Ret2Libc |
| [Web/baby ninja jinja](Challenges/Pwn/baby ninja jinja) | [ssti.py](Challenges/Pwn/baby ninja jinja/ssti.py) | Python   | SSTI. RCE. Limited interactive shell session                    |
