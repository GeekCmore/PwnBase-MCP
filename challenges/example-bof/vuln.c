#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Simplified challenge for CI testing
// Spawns a shell directly - no exploit needed
int main() {
    // Disable buffering for immediate output
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    // Give the user a shell
    system("/bin/sh");
    return 0;
}
