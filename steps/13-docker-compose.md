# Step 13 — docker-compose.yml

**Reference docs:** Read `docs/docker.md` fully before starting.

**Docker required:** Yes — this step starts all three containers together.

---

## What to Build

`docker-compose.yml` at the repository root, wiring all three containers together with correct PID namespace sharing, networking, volumes, and startup ordering.

---

## Create docker-compose.yml

Write the file exactly as specified in `docs/docker.md` under "docker-compose.yml — Full Specification". The critical elements are:

1. `pid: "service:exploit-env"` on challenge-env — must not be omitted.
2. `depends_on: exploit-env` on challenge-env — required for correct startup ordering.
3. `depends_on: pyghidra-mcp` on exploit-env — pyghidra-mcp must be ready before exploit-env tries to proxy to it.
4. pyghidra-mcp port 9090 must **not** appear in `ports:` (internal only).
5. `./challenges` mounted read-only in both exploit-env and pyghidra-mcp.
6. `ghidra-projects` named volume on pyghidra-mcp only.

Replace `<published-pyghidra-mcp-image>` with the actual upstream image name. Check the pyghidra-mcp repository for the current image tag.

---

## Verification

### 1. Start all containers

```bash
docker compose up -d --build
```

### 2. Verify all containers are running

```bash
docker compose ps
# All three containers should show status "Up"
```

### 3. Verify MCP server is reachable

```bash
curl -s http://localhost:8080/ | head -5
# Should return something (not connection refused)
```

### 4. Verify PID namespace sharing is working

```bash
# Connect to challenge port to trigger xinetd to fork a child
python3 -c "
import socket, time
s = socket.socket()
s.connect(('localhost', 4444))
time.sleep(2)
s.close()
"

# From exploit-env, list processes — should include pwn_binary
docker compose exec exploit-env ps aux | grep pwn_binary
# Should show at least one pwn_binary process
```

### 5. Verify pyghidra-mcp is reachable from exploit-env (internal network)

```bash
docker compose exec exploit-env \
    curl -s http://pyghidra-mcp:9090/ | head -5
# Should not be "connection refused"
```

### 6. Verify pyghidra-mcp is NOT reachable from host

```bash
curl -s --connect-timeout 2 http://localhost:9090/ 2>&1
# Should fail: "Connection refused" or timeout
```

### 7. Verify challenges volume is mounted

```bash
docker compose exec exploit-env ls /challenges/example-bof/
# Should list: Dockerfile  Makefile  flag  pwn_binary  vuln.c
```

### 8. Tear down

```bash
docker compose down
```

All checks must pass before proceeding to Step 14.
