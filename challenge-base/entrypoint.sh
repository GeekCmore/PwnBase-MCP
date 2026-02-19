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
