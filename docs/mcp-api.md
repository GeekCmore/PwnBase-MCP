# MCP Tool API — Full Reference

This document defines every MCP tool exposed by exploit-env's MCP server. Read this before implementing `main.py`. All tool signatures, parameter types, return shapes, and error behaviors are specified here.

---

## Server Configuration

```python
from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    name="pwn-agent",
    stateless_http=True,
    json_response=True,
)
```

Transport: Streamable HTTP on port 8080. SSE also supported. No authentication.

All tools are async. Tools that execute blocks accept a `ctx: Context[ServerSession, None]` parameter for progress streaming.

---

## Return Type Convention

All tools return a dict serialized as JSON. Success responses always include `"ok": true`. Error responses always include `"ok": false` and `"error": "<message>"`. Never raise unhandled exceptions from tool functions — catch all errors and return `{"ok": false, "error": str(e)}`.

---

## Session Management Tools

### `new_session`

```python
@mcp.tool()
async def new_session(challenge_host: str, challenge_port: int) -> dict:
```

Creates a new session, tearing down any existing one. Initializes Block 0 and executes it.

**Parameters:**
- `challenge_host`: hostname or IP of challenge-env (e.g., `"challenge"` or `"localhost"`)
- `challenge_port`: TCP port of the challenge (e.g., `4444`)

**Returns on success:**
```json
{
  "ok": true,
  "session": {
    "challenge_host": "challenge",
    "challenge_port": 4444,
    "frontier": 0,
    "pid": 12345,
    "final_flag": null,
    "blocks": [
      {
        "block_id": "...",
        "index": 0,
        "type": "exploit",
        "source": "conn = remote('challenge', 4444)\npid = <acquired by framework>",
        "status": "done",
        "output": ""
      }
    ]
  }
}
```

**Returns on failure** (e.g., connection refused):
```json
{ "ok": false, "error": "Connection refused to challenge:4444" }
```

---

### `get_session`

```python
@mcp.tool()
async def get_session() -> dict:
```

Returns the full current session state. No parameters.

**Returns on success:** Same shape as the `"session"` object in `new_session` response, with all blocks including their current `status` and `output`.

**Returns when no session exists:**
```json
{ "ok": false, "error": "No active session. Call new_session() first." }
```

---

### `reset_session`

```python
@mcp.tool()
async def reset_session() -> dict:
```

Manually triggers the full reset sequence. Re-executes Block 0.

**Returns on success:**
```json
{
  "ok": true,
  "message": "Session reset. Block 0 re-executed. frontier=0, pid=12346."
}
```

---

## Block Registry Tools

All block registry tools return `reset_triggered: bool` in their response. When `reset_triggered` is `true`, the full reset sequence has already completed before the response is returned, and `frontier` is now `0`.

### `add_block`

```python
@mcp.tool()
async def add_block(index: int, type: str, source: str) -> dict:
```

Inserts a new block at the given index. Blocks at that index and beyond are shifted down by one.

**Parameters:**
- `index`: position to insert at (1-based from Agent perspective; 0 is Block 0 and cannot be targeted)
- `type`: `"exploit"` or `"gdb"`
- `source`: block source code or GDB commands

**Validation:**
- `index` must be ≥ 1 and ≤ `len(blocks)` (appending at end is valid)
- `type` must be `"exploit"` or `"gdb"`
- `source` must be non-empty string

**Returns on success:**
```json
{
  "ok": true,
  "block_id": "uuid-...",
  "index": 1,
  "reset_triggered": false
}
```

**Returns when reset triggered:**
```json
{
  "ok": true,
  "block_id": "uuid-...",
  "index": 1,
  "reset_triggered": true,
  "reset_message": "Block inserted at index 1 which is ≤ frontier 2. Session reset."
}
```

---

### `delete_block`

```python
@mcp.tool()
async def delete_block(block_id: str) -> dict:
```

**Parameters:**
- `block_id`: UUID of the block to delete

**Validation:**
- `block_id` must exist
- `block_id` must not be Block 0's ID (returns error)

**Returns on success:**
```json
{
  "ok": true,
  "deleted_index": 2,
  "reset_triggered": false
}
```

---

### `modify_block`

```python
@mcp.tool()
async def modify_block(block_id: str, source: str) -> dict:
```

**Parameters:**
- `block_id`: UUID of the block to modify
- `source`: new source content

**Validation:**
- `block_id` must exist and must not be Block 0's ID
- `source` must be non-empty

**Returns on success:**
```json
{
  "ok": true,
  "block_id": "uuid-...",
  "index": 3,
  "reset_triggered": true,
  "reset_message": "Block at index 3 modified which is ≤ frontier 3. Session reset."
}
```

---

### `move_block`

```python
@mcp.tool()
async def move_block(block_id: str, new_index: int) -> dict:
```

**Parameters:**
- `block_id`: UUID of the block to move
- `new_index`: target index (1-based; cannot move to index 0)

**Validation:**
- `block_id` must exist and must not be Block 0's ID
- `new_index` must be ≥ 1 and ≤ `len(blocks) - 1`

**Reset trigger logic for move:** A move triggers reset if **either** the source index or the destination index is ≤ frontier.

**Returns on success:**
```json
{
  "ok": true,
  "block_id": "uuid-...",
  "old_index": 2,
  "new_index": 4,
  "reset_triggered": false
}
```

---

## Execution Engine Tools

Execution tools stream per-block output using `ctx.report_progress()`. Each progress notification has this shape:

```python
await ctx.report_progress(
    progress=blocks_done / total_blocks,
    total=1.0,
    message=json.dumps({
        "block_id": block.block_id,
        "index": block.index,
        "type": block.type,
        "status": block.status,     # "done" or "error"
        "output": block.output,
        "final_flag": session.final_flag,
    })
)
```

The final return value (after all blocks complete) also contains the full summary.

---

### `run_to`

```python
@mcp.tool()
async def run_to(
    target: str,   # block_id or stringified integer index
    ctx: Context[ServerSession, None]
) -> dict:
```

Full clean restart from Block 0 through the target block.

**Parameters:**
- `target`: either a block UUID or a stringified integer index (e.g., `"3"` or `"uuid-..."`)

**Behavior:**
1. Execute reset sequence.
2. Execute Block 0 (part of reset).
3. Execute blocks 1 through target sequentially.
4. Stop after target block or on first error.
5. Stream progress after each block.

**Returns on success:**
```json
{
  "ok": true,
  "frontier": 3,
  "final_flag": "CTF{...}",
  "blocks_executed": [
    {"index": 0, "status": "done"},
    {"index": 1, "status": "done"},
    {"index": 2, "status": "done"},
    {"index": 3, "status": "done"}
  ]
}
```

**Returns on block error:**
```json
{
  "ok": false,
  "error": "Block 2 failed with error: NameError: name 'p64' is not defined",
  "frontier": 1,
  "failed_block_index": 2,
  "blocks_executed": [...]
}
```

---

### `run_all`

```python
@mcp.tool()
async def run_all(ctx: Context[ServerSession, None]) -> dict:
```

Equivalent to `run_to` with the last block as the target. Same return shape.

---

### `step`

```python
@mcp.tool()
async def step(
    n: int = 1,
    ctx: Context[ServerSession, None] = None
) -> dict:
```

Execute the next N blocks from `frontier + 1`. No restart.

**Parameters:**
- `n`: number of blocks to execute (default: 1, minimum: 1)

**Behavior:**
1. Validate session liveness (check conn and pid). Return error if invalid.
2. Compute target range: blocks `[frontier+1, frontier+N]`.
3. If `frontier + 1 > last_block_index`, return error: `"No blocks to execute after frontier."`.
4. Execute each block in range, streaming progress.
5. Stop on first error.

**Returns on success:**
```json
{
  "ok": true,
  "frontier": 3,
  "final_flag": null,
  "blocks_executed": [
    {"index": 3, "status": "done", "output": "..."}
  ]
}
```

**Returns on liveness failure:**
```json
{
  "ok": false,
  "error": "Challenge process (pid=12345) no longer exists. It likely crashed. Use run_to() or run_all() to restart."
}
```

---

### `continue_execution`

```python
@mcp.tool()
async def continue_execution(ctx: Context[ServerSession, None]) -> dict:
```

Note: named `continue_execution` (not `continue`) because `continue` is a Python reserved keyword.

Execute all remaining blocks from `frontier + 1` through the last block. No restart. Same liveness check and return shape as `step`.

---

## Challenge Interaction Tools

### `verify_flag`

```python
@mcp.tool()
async def verify_flag(flag: str) -> dict:
```

Proxies the flag to challenge-env's POST /verify endpoint.

**Parameters:**
- `flag`: the candidate flag string (typically the value captured in `final_flag`)

**Returns on success:**
```json
{ "ok": true, "correct": true }
```
or
```json
{ "ok": true, "correct": false }
```

**Returns on network failure:**
```json
{ "ok": false, "error": "Failed to reach flag verifier: Connection refused" }
```

---

## Reverse Engineering Tools

### `analyze_binary`

```python
@mcp.tool()
async def analyze_binary(binary_path: str) -> dict:
```

**Parameters:**
- `binary_path`: absolute path to the binary inside the container (e.g., `/challenges/example-bof/pwn_binary`)

**Returns on success:**
```json
{
  "ok": true,
  "functions": [
    {"name": "main", "address": "0x401234", "size": 128},
    {"name": "vuln", "address": "0x401300", "size": 64}
  ],
  "imports": ["puts", "gets", "printf"],
  "strings": ["Enter input:", "/bin/sh"]
}
```

---

### `decompile_function`

```python
@mcp.tool()
async def decompile_function(name_or_addr: str) -> dict:
```

**Parameters:**
- `name_or_addr`: function name (e.g., `"vuln"`) or hex address (e.g., `"0x401300"`)

**Returns on success:**
```json
{
  "ok": true,
  "name": "vuln",
  "address": "0x401300",
  "source": "void vuln(void) {\n    char buf[64];\n    gets(buf);\n}"
}
```

---

### `get_xrefs`

```python
@mcp.tool()
async def get_xrefs(addr: str) -> dict:
```

**Parameters:**
- `addr`: hex address string (e.g., `"0x401300"`)

**Returns on success:**
```json
{
  "ok": true,
  "addr": "0x401300",
  "refs_to": [
    {"from": "0x401234", "type": "CALL"}
  ],
  "refs_from": [
    {"to": "0x401500", "type": "CALL"}
  ]
}
```
