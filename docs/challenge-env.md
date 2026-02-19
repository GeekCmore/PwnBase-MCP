# challenge-env — Design & Implementation Reference

This document is the full reference for the challenge-env container. Step documents (`steps/01-challenge-base.md`, `steps/02-sample-challenge.md`) will direct you here at the appropriate moments. Do not implement anything based solely on this document — follow the step documents.

---

## Purpose

challenge-env runs a CTF challenge binary over TCP and provides a flag verification endpoint. It is intentionally minimal: no Agent interface, no debugging tools, no sandbox by default. Its only job is to serve the binary reliably and verify flags.

---

## Image Hierarchy

```
challenge-base:20.04
challenge-base:22.04       ← primary development target
challenge-base:24.04
    └── challenge-<name>:latest
```

Each base image is a separate Dockerfile (`challenge-base/Dockerfile.20.04`, etc.) parameterized by the Ubuntu version. A derived challenge image adds only the binary, flag, and challenge-specific dependencies.

**Every derived image must follow these conventions:**
- Challenge binary at `/challenge/pwn_binary`
- Flag file at `/challenge/flag`
- `ENV CHALLENGE_PORT=4444`
- `ENV CHALLENGE_BINARY=/challenge/pwn_binary`
- `FROM challenge-base:<version>`

---

## Base Image Contents

Each base Dockerfile installs:
- `xinetd` — TCP service manager
- `python3` + `python3-flask` — for the flag verifier server
- Standard CTF utilities: `libc6-dbg`, `gcc`, `gdb` (for completeness)

The base image copies in three files:
- `flag_verifier.py` → `/usr/local/bin/flag_verifier.py`
- `entrypoint.sh` → `/entrypoint.sh`
- `xinetd.conf.template` → `/etc/xinetd.conf.template`

The `ENTRYPOINT` is `/entrypoint.sh`.

---

## entrypoint.sh

Executed when the container starts. Responsibilities:

1. Generate `/etc/xinetd.d/challenge` from `xinetd.conf.template` by substituting `CHALLENGE_PORT` and `CHALLENGE_BINARY` environment variables using `envsubst`.
2. Start the flag verifier in the background: `python3 /usr/local/bin/flag_verifier.py &`
3. Exec xinetd in the foreground: `exec xinetd -dontfork`

xinetd must run in the foreground (not daemonized) so Docker correctly tracks the process lifecycle.

---

## xinetd.conf.template

```
service challenge
{
    type        = UNLISTED
    protocol    = tcp
    socket_type = stream
    port        = ${CHALLENGE_PORT}
    wait        = no
    user        = nobody
    server      = ${CHALLENGE_BINARY}
    log_on_failure += USERID
    disable     = no
}
```

`wait = no` means xinetd forks a new child for every connection. This is critical: each pwntools `remote()` call corresponds to exactly one forked child process, which is how PID discovery works.

---

## Flag Verifier (flag_verifier.py)

A minimal Flask application. Implementation requirements:

- Listens on `0.0.0.0:5000`
- Reads `/challenge/flag` once at startup and stores the content (stripped of whitespace) in memory
- Exposes exactly one route: `POST /verify`
- Request body: JSON `{"flag": "<candidate>"}`
- Response: JSON `{"correct": true}` or `{"correct": false}`
- Compares the submitted flag against the stored flag using a constant-time comparison (`hmac.compare_digest`)
- **No GET /flag endpoint.** Any GET to `/verify` or any other path returns 404.
- If `/challenge/flag` does not exist at startup, log an error and exit with code 1.

```python
# Minimal structure
from flask import Flask, request, jsonify
import hmac, os, sys

app = Flask(__name__)

flag_path = "/challenge/flag"
if not os.path.exists(flag_path):
    print(f"ERROR: {flag_path} not found", file=sys.stderr)
    sys.exit(1)

with open(flag_path) as f:
    CORRECT_FLAG = f.read().strip()

@app.route("/verify", methods=["POST"])
def verify():
    data = request.get_json(force=True, silent=True) or {}
    candidate = str(data.get("flag", ""))
    correct = hmac.compare_digest(candidate, CORRECT_FLAG)
    return jsonify({"correct": correct})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
```

---

## Derived Challenge Dockerfile Pattern

```dockerfile
FROM challenge-base:22.04

COPY ./pwn_binary  /challenge/pwn_binary
COPY ./flag        /challenge/flag

RUN chmod +x /challenge/pwn_binary

ENV CHALLENGE_PORT=4444
ENV CHALLENGE_BINARY=/challenge/pwn_binary

EXPOSE 4444 5000
```

No additional entrypoint needed — it is inherited from the base image.

---

## Exposed Ports

| Port | Service | Notes |
|------|---------|-------|
| 4444 | xinetd → challenge binary | pwntools connects here |
| 5000 | Flask flag verifier | Only POST /verify |

---

## Security Notes

- No seccomp, no namespacing, no dropped capabilities by default.
- The binary runs as `nobody` (set in xinetd config).
- If a challenge requires sandbox hardening (e.g., seccomp rules), add it in the derived image only.
- The flag file should not be world-readable in production, but for CTF development this is acceptable.
