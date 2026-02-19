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
