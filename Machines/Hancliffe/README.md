# Hack The Box. Machines. Hancliffe

Machine write-up: https://7rocky.github.io/en/htb/hancliffe

### `decrypt.sh`

The purpose of this script is to decrypt a password that has been encrypted with two substitution ciphers (and encoded in Base64).

First of all, we take the ciphertext and decode it in Base64:

```bash
encrypted='YXlYeDtsbD98eDtsWms5SyU='
echo "Encrypted : $encrypted"

encrypted2=$(echo $encrypted | base64 -d)
echo "Encrypted2: $encrypted2"
```

Then, we are going to iterate over all printable characters and encrypt them using `encrypt2` compiled binary until we find a coincidence with corresponding the ciphertext character, in order to obtain the plaintext character:

```bash
for i in $(seq 1 ${#encrypted2}); do
  for d in {32..126}; do
    c=$(python3 -c "print(chr($d))")

    if [ "$(./encrypt2 $c)" = ${encrypted2:i-1:1} ]; then
      encrypted1+=$c
      break
    fi
  done
done

echo "Encrypted1: $encrypted1"
```

We do the same operation with `encrypt1`. And finally, we undo the process using the plaintext to verify that it is correct:

```bash
echo "Decrypted : $decrypted"

echo Re-compute: $(./encrypt2 "$(./encrypt1 "$decrypted")" | tr -d '\n' | base64)
```

Finally, we can obtain the decrypted password:

```console
$ bash decrypt.sh
Encrypted : YXlYeDtsbD98eDtsWms5SyU=  
Encrypted2: ayXx;ll?|x;lZk9K%
Encrypted1: zbCc;oo?|c;oAp9P%
Decrypted : K3r4j@@nM4j@pAh!T
Re-compute: YXlYeDtsbD98eDtsWms5SyU=
```

### `encrypt1.c` and `encrypt2.c`

These C scripts are adaptations for ROT47 and Atbash ciphers found in `MyFirstApp.exe` binary file when analyzing the decompiled C source code in Ghidra.

They are meant to be compiled with `gcc` and use passing the plaintext as a command line argument:

```console
$ gcc -o encrypt1 encrypt1.c

$ gcc -o encrypt2 encrypt2.c

$ chars="$(python3 -c 'import string; print(string.printable.strip())')"

$ echo $chars; ./encrypt1 "$chars"
0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
_`abcdefgh23456789:;<=>?@ABCDEFGHIJKpqrstuvwxyz{|}~!"#$%&'()*+PQRSTUVWXYZ[\]^ijklmno,-./01LMNO

$ echo $chars; ./encrypt2 "$chars"
0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
0123456789zyxwvutsrqponmlkjihgfedcbaZYXWVUTSRQPONMLKJIHGFEDCBA!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~
```

### `exploit.py`

The [write-up](https://7rocky.github.io/en/htb/hancliffe) provides all the explanation for this script.
