# Step 01 — Challenge Base Images

**Reference docs:** Read `docs/challenge-env.md` fully before starting this step.

**Docker required:** No (you're writing Dockerfiles and scripts, not running them yet).

---

## What to Build

Three Dockerfiles and three supporting files that form the base layer for all challenge images.

---

## Files to Create

### `challenge-base/Dockerfile.20.04`

```dockerfile
FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    xinetd \
    python3 \
    python3-pip \
    python3-flask \
    libc6-dbg \
    gcc \
    gdb \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /challenge

COPY flag_verifier.py   /usr/local/bin/flag_verifier.py
COPY entrypoint.sh      /entrypoint.sh
COPY xinetd.conf.template /etc/xinetd.conf.template

RUN chmod +x /entrypoint.sh

EXPOSE 4444 5000

ENTRYPOINT ["/entrypoint.sh"]
```

Create identical `Dockerfile.22.04` and `Dockerfile.24.04` with `FROM ubuntu:22.04` and `FROM ubuntu:24.04` respectively. The rest of each file is identical.

---

### `challenge-base/entrypoint.sh`

```bash
#!/bin/bash
set -e

# Substitute env vars into xinetd config template
envsubst < /etc/xinetd.conf.template > /etc/xinetd.d/challenge

# Ensure challenge dir exists and binary is executable
chmod +x "${CHALLENGE_BINARY}"

# Start flag verifier in background
python3 /usr/local/bin/flag_verifier.py &

# Run xinetd in foreground (not daemonized)
exec xinetd -dontfork
```

---

### `challenge-base/xinetd.conf.template`

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

---

### `challenge-base/flag_verifier.py`

Implement this exactly as specified in `docs/challenge-env.md` under "Flag Verifier". Key requirements:

- Reads `/challenge/flag` at startup; exits with code 1 if missing.
- POST `/verify` only; no GET endpoint.
- Uses `hmac.compare_digest` for comparison.
- Listens on `0.0.0.0:5000`.

---

## Verification

You cannot fully test this step without Docker and a derived image. Instead, verify the static correctness of the files:

### 1. Validate flag_verifier.py syntax
```bash
python3 -m py_compile challenge-base/flag_verifier.py && echo "OK"
```

### 2. Validate entrypoint.sh syntax
```bash
bash -n challenge-base/entrypoint.sh && echo "OK"
```

### 3. Verify xinetd template has correct variable placeholders
```bash
grep -E '\$\{CHALLENGE_PORT\}|\$\{CHALLENGE_BINARY\}' \
    challenge-base/xinetd.conf.template && echo "Template variables OK"
```

### 4. Verify all three Dockerfiles exist and reference the correct base image
```bash
grep "FROM ubuntu:20.04" challenge-base/Dockerfile.20.04 && echo "20.04 OK"
grep "FROM ubuntu:22.04" challenge-base/Dockerfile.22.04 && echo "22.04 OK"
grep "FROM ubuntu:24.04" challenge-base/Dockerfile.24.04 && echo "24.04 OK"
```

All checks must pass before proceeding to Step 02.
