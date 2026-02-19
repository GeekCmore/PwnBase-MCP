# Pwn Agent Environment — Claude Code Master Guide

This document is the entry point for building the Pwn Agent Environment from scratch. Read it fully before doing anything. It describes the project, the technology stack, the module structure, how testing works, and how to navigate the rest of the documentation hierarchy.

---

## What This Project Is

A three-container CTF exploit development platform designed for AI Agents. It provides a structured, reproducible workspace for reverse engineering, exploit writing, and interactive debugging of binary CTF challenges. The Agent interacts exclusively through a single MCP HTTP server.

There are three containers:

- **challenge-env** — runs the CTF challenge binary under xinetd, exposes a TCP port for pwntools connections, and provides a flag verification REST endpoint. The Agent never calls this directly.
- **exploit-env** — hosts the MCP HTTP server, a persistent Python interpreter with pwntools, and pwndbg for debugging. This is the only container the Agent interacts with.
- **pyghidra-mcp** — a pre-built third-party container providing Ghidra reverse engineering via HTTP. Proxied through exploit-env. The Agent never calls this directly.

The key architectural constraint: challenge-env joins exploit-env's PID namespace, so pwndbg running in exploit-env can attach to challenge processes directly by PID.

---

## Repository Layout

```
pwn-agent-env/
├── CLAUDE.md                          ← you are here
├── docs/
│   ├── challenge-env.md               ← challenge-env design + implementation guide
│   ├── exploit-env.md                 ← exploit-env container setup guide
│   ├── session-model.md               ← session, blocks, frontier, reset logic
│   ├── mcp-api.md                     ← all MCP tools, signatures, behavior
│   └── docker.md                      ← docker-compose, networking, volumes
├── steps/                             ← read the relevant step doc before implementing
│   ├── 01-challenge-base.md
│   ├── 02-sample-challenge.md
│   ├── 03-exploit-env-dockerfile.md
│   ├── 04-proc-utils.md
│   ├── 05-session.md
│   ├── 06-interpreter.md
│   ├── 07-gdb-controller.md
│   ├── 08-block-registry.md
│   ├── 09-execution-engine.md
│   ├── 10-challenge-client.md
│   ├── 11-ghidra-proxy.md
│   ├── 12-mcp-server.md
│   ├── 13-docker-compose.md
│   └── 14-integration-test.md
├── challenge-base/
│   ├── Dockerfile.20.04
│   ├── Dockerfile.22.04
│   ├── Dockerfile.24.04
│   ├── flag_verifier.py
│   ├── entrypoint.sh
│   └── xinetd.conf.template
├── exploit-env/
│   ├── Dockerfile
│   ├── pyproject.toml
│   └── mcp_server/
│       ├── __init__.py
│       ├── main.py
│       ├── session.py
│       ├── block_registry.py
│       ├── execution_engine.py
│       ├── interpreter.py
│       ├── gdb_controller.py
│       ├── proc_utils.py
│       ├── challenge_client.py
│       └── ghidra_proxy.py
├── challenges/
│   └── example-bof/
│       ├── Dockerfile
│       ├── vuln.c
│       ├── pwn_binary          ← compiled from vuln.c
│       └── flag
└── tests/
    ├── unit/
    │   ├── test_proc_utils.py
    │   ├── test_session.py
    │   ├── test_interpreter.py
    │   ├── test_gdb_controller.py
    │   ├── test_block_registry.py
    │   └── test_execution_engine.py
    ├── integration/
    │   ├── test_mcp_server.py
    │   └── test_full_stack.py
    └── conftest.py
```

---

## Technology Stack

### Python Environment
- **Runtime**: Python 3.11+
- **Package manager**: `uv` — use `uv` for all dependency management, never `pip` directly
- **Project file**: `exploit-env/pyproject.toml` defines all Python dependencies
- **Key dependencies**:
  - `pwntools` — CTF exploit framework; provides `remote()`, `flat()`, `p64()`, `cyclic()`, etc.
  - `mcp[cli]` — official MCP Python SDK; provides `FastMCP`, `Context`, progress notifications
  - `httpx` — async HTTP client for proxying to flag verifier and pyghidra-mcp
  - `pytest` + `pytest-asyncio` — test runner
  - `pytest-mock` — mocking for unit tests

### MCP Server
- **Framework**: `FastMCP` from the official MCP Python SDK (`modelcontextprotocol/python-sdk`)
- **Transport**: Streamable HTTP (primary) and SSE (also supported)
- **Port**: 8080
- **Streaming**: long-running execution tools use `ctx.report_progress()` to stream per-block output as each block completes
- **Tool definition pattern**:
  ```python
  from mcp.server.fastmcp import FastMCP, Context
  from mcp.server.session import ServerSession

  mcp = FastMCP("pwn-agent", stateless_http=True, json_response=True)

  @mcp.tool()
  async def my_tool(param: str, ctx: Context[ServerSession, None]) -> str:
      await ctx.report_progress(progress=0.5, total=1.0, message="working...")
      return "result"

  if __name__ == "__main__":
      mcp.run(transport="streamable-http")
  ```

### Containers
- **Base images**: `ubuntu:20.04`, `ubuntu:22.04`, `ubuntu:24.04`
- **Orchestration**: `docker compose` (v2 syntax)
- **PID sharing**: `pid: "service:exploit-env"` on challenge-env
- **pyghidra-mcp**: pulled from upstream; no custom Dockerfile

### Challenge Environment
- **Service manager**: `xinetd` — forks one child per TCP connection
- **Flag verifier**: minimal Flask HTTP server
- **Challenge binary**: compiled C, served via xinetd

---

## Module Division

All Python source lives in `exploit-env/mcp_server/`. Each module has exactly one responsibility:

| Module | Responsibility |
|---|---|
| `main.py` | FastMCP server instantiation and tool registration |
| `session.py` | PwnSession dataclass; global session state; reset sequence |
| `block_registry.py` | Block CRUD; frontier-aware reset triggering |
| `execution_engine.py` | run_to / run_all / step / continue; progress streaming |
| `interpreter.py` | Persistent Python interpreter; conn/pid injection; final_flag extraction |
| `gdb_controller.py` | pwndbg subprocess; attach / execute commands / detach |
| `proc_utils.py` | /proc scanning; PID discovery; challenge child cleanup |
| `challenge_client.py` | HTTP proxy to flag verifier REST endpoint |
| `ghidra_proxy.py` | HTTP proxy to pyghidra-mcp RE tools |

Read `docs/session-model.md` for the full conceptual model before implementing any of these modules. Read `docs/mcp-api.md` for all tool signatures and contracts before implementing `main.py`.

---

## Testing Strategy

There are three test levels. Each has different Docker requirements.

### Level 1: Unit Tests (`tests/unit/`)
**No Docker required.** Run directly on the developer's machine using `uv run pytest tests/unit/`.

Each module in `mcp_server/` has a corresponding unit test file. External dependencies (subprocess calls to gdb, /proc filesystem, HTTP calls) are mocked using `pytest-mock`. Unit tests verify logic correctness in isolation.

### Level 2: MCP Integration Tests (`tests/integration/test_mcp_server.py`)
**Requires exploit-env and pyghidra-mcp containers running** (challenge-env not required). Start with:
```bash
docker compose up exploit-env pyghidra-mcp -d
uv run pytest tests/integration/test_mcp_server.py
```
Tests call MCP tools through the official Python SDK client (`mcp.client.streamable_http`) and verify tool responses, error handling, and streaming behavior.

### Level 3: Full-Stack Tests (`tests/integration/test_full_stack.py`)
**Requires all three containers running.** Start with:
```bash
docker compose up -d
uv run pytest tests/integration/test_full_stack.py
```
Tests use the `example-bof` challenge to verify the complete exploit workflow: session creation, block execution, GDB attachment, flag capture, and verification. See `steps/14-integration-test.md` for the test binary and expected workflow.

---

## Deployment

To run the full environment against a specific challenge:

```bash
# 1. Build challenge image (first time or after changes)
docker compose build challenge-env

# 2. Start all containers
docker compose up -d

# 3. Verify MCP server is responding
curl http://localhost:8080/

# 4. Point the Agent at the MCP server
# MCP endpoint: http://localhost:8080/mcp

# 5. Tear down
docker compose down
```

To switch challenges, update the `challenge-env` build context in `docker-compose.yml` to point to the new challenge directory and rebuild.

---

## CI/CD and GitHub Workflows

The project uses GitHub Actions to automate container image builds and publish them to the GitHub Container Registry (ghcr.io). Workflow definitions live in `.github/workflows/`.

### Workflow Structure

```
.github/
└── workflows/
    ├── build-challenge-base.yml     ← builds challenge base images (implemented)
    └── build-exploit-env.yml        ← builds MCP server image (to be implemented)
```

### Challenge Base Workflow (`build-challenge-base.yml`)

Builds and publishes three Ubuntu base images used by all CTF challenge containers.

**Triggers:**
- Push to `main` branch when `challenge-base/**` or the workflow file itself changes
- Git tags matching `v*.*.*` (for versioned releases)
- Manual trigger via `workflow_dispatch` (GitHub UI "Run workflow" button)

**Matrix Build:**
- Ubuntu versions: `20.04`, `22.04`, `24.04`
- Each version builds in parallel as a separate job

**Tagging Strategy:**
- `latest` tag: `ghcr.io/<repo>/challenge-base:<version>-latest`
  - Updated on every push to main
- Versioned tags: `ghcr.io/<repo>/challenge-base:<version>-<release>`
  - Created only when pushing version tags (e.g., `v1.0.0`)

**Registry:**
- Images push to `ghcr.io`
- Uses `GITHUB_TOKEN` for authentication (automatic for repo workflows)
- Requires `packages: write` permission

**Repository Name Handling:**
Docker tags require lowercase repository names. The workflow converts `github.repository` to lowercase using `tr '[:upper:]' '[:lower:]'` before constructing image tags.

**Build Optimization:**
- Uses GitHub Actions cache (`cache-from`/`cache-to: type=gha`)
- Multi-platform support: `linux/amd64` (extendable to `linux/arm64`)

### Exploit-env Workflow (Future)

The `build-exploit-env.yml` workflow will follow the same pattern as `build-challenge-base.yml`:

- Triggers on changes to `exploit-env/**` or workflow file
- Builds the MCP server container image
- Tags as `ghcr.io/<repo>/exploit-env:latest` (and versioned on release)
- Can include `pyproject.toml` hash in labels for cache-busting dependencies

### Path Filtering

Both workflows use `paths` filters to avoid unnecessary builds:
```yaml
paths:
  - 'challenge-base/**'
  - '.github/workflows/build-challenge-base.yml'
```
Only pushes that modify these paths trigger the workflow.

### Manual Workflow Invocation

To trigger a build without pushing code:

1. Go to the GitHub repository → Actions tab
2. Select "Build Challenge Base Images" workflow
3. Click "Run workflow"
4. Select branch and click "Run workflow"

This is useful for rebuilding images after upstream base image updates or for testing workflow changes.

---

## How to Use This Documentation

**You build this project by following the steps in order.** Each step has its own document in `steps/`. Before starting any step:

1. Read the step document fully.
2. Read any referenced `docs/` files it points to.
3. Implement exactly what the step specifies.
4. Run the verification commands at the end of the step document.
5. **Commit your changes** after verification passes (see Commit Workflow below).
6. Do not proceed to the next step until verification passes.

### Commit Workflow

After completing each step and passing verification, commit your changes with a descriptive message:

```bash
# Stage the new/modified files for the step
git add <files-from-step>

# Commit with a clear message
git commit -m "Step <NN>: <brief description>

<detailed explanation of what was added/changed>

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

Each step should result in exactly one git commit. This creates a clean, bisectable history where each commit corresponds to a logical step in the build process.

**Start here: read `steps/01-challenge-base.md` now.**

If you need to understand the broader design of a subsystem before implementing it, the `docs/` files contain the full reference. The step documents reference them at the appropriate moments — do not read the `docs/` files ahead of time unless a step document directs you to.

When a step's implementation requires a design decision not covered by the step document, make the simplest reasonable choice, implement it, and add a `# NOTE:` comment explaining the decision.
