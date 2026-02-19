#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void win() {
    char flag[64];
    FILE *f = fopen("/challenge/flag", "r");
    if (f == NULL) {
        puts("Flag file not found.");
        exit(1);
    }
    fgets(flag, sizeof(flag), f);
    fclose(f);
    puts(flag);
    fflush(stdout);
}

void vuln() {
    char buf[64];
    printf("Enter input: ");
    fflush(stdout);
    gets(buf);
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);
    vuln();
    return 0;
}

// COMPILER_FLAGS: -m64 -fno-stack-protector -no-pie -z execstack -w
// Exploit details (Ubuntu 22.04):
//   win() address: varies by build - extract from ELF
//   Buffer offset: 72 bytes (64 buf + 8 saved RBP)
