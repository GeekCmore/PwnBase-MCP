# Step 12 — main.py (MCP Server)

**Reference docs:** Read `docs/mcp-api.md` fully before starting. Every tool signature, return shape, and error behavior is specified there.

**Docker required:** No for unit tests. Yes for MCP integration tests.

---

## What to Build

`exploit-env/mcp_server/main.py` — the FastMCP server that wires all modules together and registers every tool. This is the last Python module to implement. After this step, the MCP server is runnable.

---

## Server Setup

```python
from mcp.server.fastmcp import FastMCP, Context
from mcp.server.session import ServerSession
import os

mcp = FastMCP(
    name="pwn-agent",
    stateless_http=True,
    json_response=True,
)
```

Run with:
```python
if __name__ == "__main__":
    port = int(os.environ.get("MCP_PORT", "8080"))
    mcp.run(transport="streamable-http", port=port, host="0.0.0.0")
```

---

## Module-Level Session State

`main.py` holds the global session reference and passes it to all tool functions:

```python
from mcp_server import session as session_module
from mcp_server import block_registry, execution_engine
from mcp_server import challenge_client, ghidra_proxy

_session = None   # set by new_session tool
```

---

## Tool Implementations

Implement all tools exactly as specified in `docs/mcp-api.md`. Below is the skeleton for each tool showing how modules are called. Fill in the full error handling per the API spec.

### Session tools

```python
@mcp.tool()
async def new_session(challenge_host: str, challenge_port: int) -> dict:
    global _session
    try:
        if _session is not None:
            session_module.reset(_session)  # tear down existing
        _session = session_module.create_session(challenge_host, challenge_port)
        return {"ok": True, "session": session_module.to_dict(_session)}
    except Exception as e:
        return {"ok": False, "error": str(e)}

@mcp.tool()
async def get_session() -> dict:
    if _session is None:
        return {"ok": False, "error": "No active session. Call new_session() first."}
    return {"ok": True, "session": session_module.to_dict(_session)}

@mcp.tool()
async def reset_session() -> dict:
    if _session is None:
        return {"ok": False, "error": "No active session."}
    try:
        session_module.reset(_session)
        return {"ok": True, "message": f"Session reset. frontier=0, pid={_session.pid}."}
    except Exception as e:
        return {"ok": False, "error": str(e)}
```

### Block registry tools

```python
@mcp.tool()
async def add_block(index: int, type: str, source: str) -> dict:
    if _session is None:
        return {"ok": False, "error": "No active session."}
    try:
        return {"ok": True, **block_registry.add_block(_session, index, type, source)}
    except (ValueError, RuntimeError) as e:
        return {"ok": False, "error": str(e)}

@mcp.tool()
async def delete_block(block_id: str) -> dict:
    ...

@mcp.tool()
async def modify_block(block_id: str, source: str) -> dict:
    ...

@mcp.tool()
async def move_block(block_id: str, new_index: int) -> dict:
    ...
```

### Execution tools

```python
@mcp.tool()
async def run_to(target: str, ctx: Context[ServerSession, None]) -> dict:
    if _session is None:
        return {"ok": False, "error": "No active session."}
    # Resolve target: try as block_id first, then as integer index
    resolved_index = _resolve_target(_session, target)
    if resolved_index is None:
        return {"ok": False, "error": f"Block not found: {target}"}
    return await execution_engine.run_to(_session, resolved_index, ctx)

@mcp.tool()
async def run_all(ctx: Context[ServerSession, None]) -> dict:
    if _session is None:
        return {"ok": False, "error": "No active session."}
    last_index = len(_session.blocks) - 1
    return await execution_engine.run_to(_session, last_index, ctx)

@mcp.tool()
async def step(n: int = 1, ctx: Context[ServerSession, None] = None) -> dict:
    if _session is None:
        return {"ok": False, "error": "No active session."}
    return await execution_engine.step(_session, n, ctx)

@mcp.tool()
async def continue_execution(ctx: Context[ServerSession, None]) -> dict:
    if _session is None:
        return {"ok": False, "error": "No active session."}
    return await execution_engine.continue_execution(_session, ctx)
```

### Target resolution helper

```python
def _resolve_target(session, target: str) -> int | None:
    """Resolve target as block_id or integer index. Returns index or None."""
    # Try integer index
    try:
        idx = int(target)
        if 0 <= idx < len(session.blocks):
            return idx
    except ValueError:
        pass
    # Try block_id
    for block in session.blocks:
        if block.block_id == target:
            return block.index
    return None
```

### Challenge and RE tools

```python
@mcp.tool()
async def verify_flag(flag: str) -> dict:
    if _session is None:
        return {"ok": False, "error": "No active session."}
    return await challenge_client.verify_flag(
        flag, _session.challenge_host
    )

@mcp.tool()
async def analyze_binary(binary_path: str) -> dict:
    return await ghidra_proxy.analyze_binary(binary_path)

@mcp.tool()
async def decompile_function(name_or_addr: str) -> dict:
    return await ghidra_proxy.decompile_function(name_or_addr)

@mcp.tool()
async def get_xrefs(addr: str) -> dict:
    return await ghidra_proxy.get_xrefs(addr)
```

---

## MCP Integration Tests

Create `tests/integration/test_mcp_server.py`.

**Requires exploit-env and pyghidra-mcp containers running.** challenge-env is not required for these tests.

```bash
docker compose up exploit-env pyghidra-mcp -d
```

Use the MCP Python SDK client:

```python
import asyncio
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

MCP_URL = "http://localhost:8080/mcp"

async def call_tool(tool_name: str, args: dict) -> dict:
    async with streamable_http_client(MCP_URL) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            result = await session.call_tool(tool_name, args)
            import json
            return json.loads(result.content[0].text)
```

### Test: get_session returns error when no session

```python
async def test_get_session_no_session():
    result = await call_tool("get_session", {})
    assert result["ok"] is False
    assert "No active session" in result["error"]
```

### Test: add_block returns error when no session

```python
async def test_add_block_no_session():
    result = await call_tool("add_block", {"index": 1, "type": "exploit", "source": "x=1"})
    assert result["ok"] is False
```

### Test: add_block rejects index 0

```python
async def test_add_block_index_zero_rejected():
    # First create a session (needs challenge running — skip if unavailable)
    pytest.skip("Requires challenge-env")
```

### Test: MCP server lists all expected tools

```python
async def test_tools_registered():
    async with streamable_http_client(MCP_URL) as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = await session.list_tools()
            tool_names = {t.name for t in tools.tools}

    expected = {
        "new_session", "get_session", "reset_session",
        "add_block", "delete_block", "modify_block", "move_block",
        "run_to", "run_all", "step", "continue_execution",
        "verify_flag", "analyze_binary", "decompile_function", "get_xrefs",
    }
    assert expected.issubset(tool_names)
```

---

## Run Integration Tests

```bash
# Start containers
docker compose up exploit-env pyghidra-mcp -d

# Wait for server to be ready
sleep 5

# Run tests
cd exploit-env
uv run pytest ../tests/integration/test_mcp_server.py -v

# Tear down
docker compose down
```

All tests must pass before proceeding to Step 13.
