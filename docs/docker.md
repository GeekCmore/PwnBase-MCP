# Docker — Compose & Networking Reference

This document specifies the docker-compose configuration, networking topology, volume layout, and startup ordering. Read before implementing `steps/13-docker-compose.md`.

---

## docker-compose.yml — Full Specification

```yaml
services:

  pyghidra-mcp:
    image: <published-pyghidra-mcp-image>   # pull from upstream; no build
    volumes:
      - ./challenges:/challenges:ro
      - ghidra-projects:/ghidra/projects
    environment:
      - GHIDRA_PROJECTS_DIR=/ghidra/projects
    # Port 9090 intentionally NOT exposed to host
    restart: unless-stopped

  exploit-env:
    build:
      context: ./exploit-env
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    volumes:
      - ./challenges:/challenges:ro
    environment:
      - PYGHIDRA_MCP_URL=http://pyghidra-mcp:9090
      - MCP_PORT=8080
    depends_on:
      - pyghidra-mcp
    restart: unless-stopped

  challenge-env:
    build:
      context: ./challenges/example-bof
      dockerfile: Dockerfile
    pid: "service:exploit-env"        # ← critical: joins exploit-env PID namespace
    ports:
      - "4444:4444"
      - "5000:5000"
    depends_on:
      - exploit-env
    restart: unless-stopped

volumes:
  ghidra-projects:
```

---

## PID Namespace — Detailed Explanation

`pid: "service:exploit-env"` instructs Docker to make challenge-env share exploit-env's PID namespace rather than having its own. The effect:

- All processes in challenge-env are visible in exploit-env's `/proc/` with their real PIDs.
- `gdb attach <pid>` in exploit-env works directly on challenge processes.
- exploit-env does NOT need `pid: host` — it only needs challenge-env to join its namespace.
- challenge-env's processes appear in exploit-env's `/proc/<pid>/` and in the output of `ps aux`.

**Startup ordering:** exploit-env must be fully started before challenge-env, because challenge-env needs exploit-env's PID namespace to exist. The `depends_on` constraint ensures this. Without it, Docker may start challenge-env before exploit-env's namespace is ready, causing a startup failure.

---

## Network Topology

All services share the default Docker Compose bridge network (named `<project>_default`). Service names are DNS-resolvable within this network:

| From | To | DNS name | Port |
|------|-----|----------|------|
| exploit-env | challenge-env | `challenge` | 4444 (xinetd), 5000 (flag verifier) |
| exploit-env | pyghidra-mcp | `pyghidra-mcp` | 9090 |
| host | exploit-env | `localhost` | 8080 |
| host | challenge-env | `localhost` | 4444, 5000 |

`pyghidra-mcp` port 9090 is **not** in the `ports:` section, so it is only reachable from within the Docker network. This is intentional — the Agent should not call pyghidra-mcp directly.

---

## Volume Layout

| Name | Type | Mounted at | Purpose |
|------|------|------------|---------|
| `./challenges` | bind mount | `/challenges` (exploit-env, pyghidra-mcp) | Challenge binaries and flags |
| `ghidra-projects` | named volume | `/ghidra/projects` (pyghidra-mcp) | Persists Ghidra analysis across restarts |

The `./challenges` bind mount is read-only in both containers (`ro`). exploit-env needs it so ghidra_proxy.py can pass absolute paths to pyghidra-mcp. pyghidra-mcp needs it to analyze binaries directly from disk.

---

## Switching Challenges

To run a different challenge, update the `context` path in the `challenge-env` service:

```yaml
challenge-env:
  build:
    context: ./challenges/my-other-challenge   # ← change this
```

Then rebuild: `docker compose build challenge-env && docker compose up -d challenge-env`

---

## Useful Commands

```bash
# Start all services
docker compose up -d

# Start with build (after Dockerfile changes)
docker compose up -d --build

# Start only infrastructure (no challenge)
docker compose up -d exploit-env pyghidra-mcp

# View logs
docker compose logs -f exploit-env
docker compose logs -f challenge-env

# Restart just the challenge (e.g., after binary change)
docker compose restart challenge-env

# Full teardown (keeps named volumes)
docker compose down

# Full teardown including volumes (destroys Ghidra projects cache)
docker compose down -v

# Shell into exploit-env for debugging
docker compose exec exploit-env bash

# Check PID namespace sharing is working
docker compose exec exploit-env ps aux | grep pwn_binary
```
