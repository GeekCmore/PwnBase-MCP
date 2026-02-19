# Step 09 — execution_engine.py

**Reference docs:** `docs/session-model.md` (sections "Exploit Block Execution", "GDB Block Execution", "Liveness Check"), `docs/mcp-api.md` (section "Execution Engine Tools")

**Docker required:** No for unit tests.

---

## What to Build

`exploit-env/mcp_server/execution_engine.py` — the four execution functions: `run_to`, `run_all`, `step`, `continue_execution`. This module orchestrates block execution by calling interpreter and gdb_controller, handles progress streaming, and manages final_flag extraction.

---

## Interface Contract

```python
from mcp.server.fastmcp import Context
from mcp.server.session import ServerSession
from mcp_server.session import PwnSession

async def run_to(
    session: PwnSession,
    target: int,                              # resolved block index
    ctx: Context[ServerSession, None],
) -> dict:
    """
    Full clean restart from Block 0 through block at target index.
    Calls session.reset() first (which re-executes Block 0).
    Then executes blocks 1..target sequentially.
    Streams progress after each block via ctx.report_progress().
    Returns execution summary dict (see docs/mcp-api.md).
    """

async def run_all(
    session: PwnSession,
    ctx: Context[ServerSession, None],
) -> dict:
    """Equivalent to run_to(session, last_block_index, ctx)."""

async def step(
    session: PwnSession,
    n: int,
    ctx: Context[ServerSession, None],
) -> dict:
    """
    Execute next n blocks from frontier+1.
    Calls session.check_liveness() first; returns error dict if invalid.
    Does NOT reset.
    Streams progress.
    Returns execution summary dict.
    """

async def continue_execution(
    session: PwnSession,
    ctx: Context[ServerSession, None],
) -> dict:
    """
    Execute all blocks from frontier+1 through last block.
    Same liveness check, no reset, streams progress.
    """
```

---

## Implementation Notes

### Progress notification format

After each block executes, call:

```python
import json

await ctx.report_progress(
    progress=blocks_done / total_blocks,
    total=1.0,
    message=json.dumps({
        "block_id": block.block_id,
        "index": block.index,
        "type": block.type,
        "status": block.status,
        "output": block.output,
        "final_flag": session.final_flag,
    })
)
```

### Block execution dispatch

```python
def _execute_block(session: PwnSession, block: Block) -> None:
    """
    Execute a single block, updating block.status, block.output,
    session.frontier, and session.final_flag as appropriate.
    Does NOT stream progress — that is the caller's responsibility.
    Raises RuntimeError on block error (status is set to "error" before raising).
    """
    block.status = "running"

    if block.type == "exploit":
        _execute_exploit_block(session, block)
    elif block.type == "gdb":
        _execute_gdb_block(session, block)
    else:
        raise ValueError(f"Unknown block type: {block.type}")
```

### Exploit block execution

```python
def _execute_exploit_block(session: PwnSession, block: Block) -> None:
    stdout, stderr = session.interpreter.execute(block.source)
    block.output = stdout + (f"\n[stderr]\n{stderr}" if stderr else "")

    if stderr:
        block.status = "error"
        raise RuntimeError(f"Block {block.index} failed:\n{stderr}")

    block.status = "done"
    session.frontier = block.index

    # final_flag extraction
    flag_value = session.interpreter.get_var("final_flag")
    if flag_value is not None:
        session.final_flag = str(flag_value)

    # Terminal operation warning
    terminal_ops = ["conn.interactive()", "conn.recvall()", "conn.close()"]
    for op in terminal_ops:
        if op in block.source:
            block.output += (
                f"\nWARNING: '{op}' is a terminal operation. "
                f"Subsequent blocks will not be able to use conn."
            )
```

### GDB block execution

```python
def _execute_gdb_block(session: PwnSession, block: Block) -> None:
    from mcp_server.gdb_controller import GdbController

    if session.gdb is not None:
        session.gdb.kill()
        session.gdb = None

    gdb = GdbController()
    try:
        gdb.attach(session.pid)
        commands = [line for line in block.source.splitlines() if line.strip()]
        output = gdb.execute_commands(commands)
        gdb.detach()
        session.gdb = None
        block.output = output
        block.status = "done"
        session.frontier = block.index
    except Exception as e:
        gdb.kill()
        session.gdb = None
        block.status = "error"
        block.output = str(e)
        raise RuntimeError(f"GDB block {block.index} failed: {e}") from e
```

### run_to / run_all core loop

```python
async def run_to(session, target, ctx):
    from mcp_server.session import reset
    reset(session)   # Block 0 is re-executed by reset

    # Blocks 1..target
    blocks_to_run = [b for b in session.blocks if 1 <= b.index <= target]
    total = len(blocks_to_run) + 1   # +1 for Block 0 already done
    blocks_executed = [{"index": 0, "status": "done"}]

    for i, block in enumerate(blocks_to_run):
        try:
            _execute_block(session, block)
        except RuntimeError as e:
            await ctx.report_progress(
                progress=(i + 1) / total, total=1.0,
                message=json.dumps({...block error state...})
            )
            return {
                "ok": False,
                "error": str(e),
                "frontier": session.frontier,
                "failed_block_index": block.index,
                "blocks_executed": blocks_executed,
            }

        await ctx.report_progress(
            progress=(i + 2) / total, total=1.0,
            message=json.dumps({...block done state...})
        )
        blocks_executed.append({"index": block.index, "status": block.status})

    return {
        "ok": True,
        "frontier": session.frontier,
        "final_flag": session.final_flag,
        "blocks_executed": blocks_executed,
    }
```

### step / continue_execution liveness check

```python
async def step(session, n, ctx):
    ok, error_msg = session_module.check_liveness(session)
    if not ok:
        return {"ok": False, "error": error_msg}

    start = session.frontier + 1
    end = min(start + n - 1, len(session.blocks) - 1)

    if start > len(session.blocks) - 1:
        return {"ok": False, "error": "No blocks to execute after current frontier."}

    blocks_to_run = session.blocks[start:end + 1]
    # ... same execution loop as run_to but without the reset
```

---

## Unit Tests

Create `tests/unit/test_execution_engine.py`.

Mock `session.reset`, `interpreter.execute`, `gdb_controller.GdbController`, and `ctx.report_progress`.

### Test: run_to calls reset before executing

```python
async def test_run_to_calls_reset(mocker):
    session = make_test_session(mocker, num_blocks=2, frontier=2)
    mock_reset = mocker.patch("mcp_server.session.reset")
    mock_ctx = mocker.MagicMock()
    mock_ctx.report_progress = mocker.AsyncMock()
    session.interpreter.execute.return_value = ("output", "")

    from mcp_server.execution_engine import run_to
    await run_to(session, 1, mock_ctx)

    mock_reset.assert_called_once_with(session)
```

### Test: run_to stops on first error

```python
async def test_run_to_stops_on_error(mocker):
    session = make_test_session(mocker, num_blocks=3)
    mocker.patch("mcp_server.session.reset")
    mock_ctx = mocker.MagicMock()
    mock_ctx.report_progress = mocker.AsyncMock()

    # Block 1 fails, block 2 should not run
    call_count = 0
    def execute_side_effect(source):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return ("", "NameError: name 'x' is not defined\n")
        return ("ok", "")

    session.interpreter.execute.side_effect = execute_side_effect

    from mcp_server.execution_engine import run_to
    result = await run_to(session, 2, mock_ctx)

    assert result["ok"] is False
    assert call_count == 1   # block 2 never ran
```

### Test: step returns error when pid dead

```python
async def test_step_returns_error_when_dead(mocker):
    session = make_test_session(mocker, num_blocks=2, frontier=0)
    mocker.patch(
        "mcp_server.session.check_liveness",
        return_value=(False, "process crashed")
    )
    mock_ctx = mocker.MagicMock()

    from mcp_server.execution_engine import step
    result = await step(session, 1, mock_ctx)

    assert result["ok"] is False
    assert "process crashed" in result["error"]
```

### Test: final_flag is extracted after exploit block

```python
async def test_final_flag_extracted(mocker):
    session = make_test_session(mocker, num_blocks=1, frontier=0)
    mocker.patch("mcp_server.session.reset")
    mock_ctx = mocker.MagicMock()
    mock_ctx.report_progress = mocker.AsyncMock()
    session.interpreter.execute.return_value = ("CTF{test}", "")
    session.interpreter.get_var.return_value = "CTF{test_flag}"

    from mcp_server.execution_engine import run_to
    result = await run_to(session, 1, mock_ctx)

    assert session.final_flag == "CTF{test_flag}"
    assert result["final_flag"] == "CTF{test_flag}"
```

### Test: terminal op warning appended to output

```python
async def test_terminal_op_warning(mocker):
    session = make_test_session(mocker, num_blocks=1, frontier=0)
    mocker.patch("mcp_server.session.reset")
    mock_ctx = mocker.MagicMock()
    mock_ctx.report_progress = mocker.AsyncMock()
    session.interpreter.execute.return_value = ("", "")
    session.interpreter.get_var.return_value = None

    # Add block with terminal op
    from mcp_server.session import Block
    session.blocks.append(Block("b1", 1, "exploit", "conn.interactive()"))

    from mcp_server.execution_engine import run_to
    await run_to(session, 1, mock_ctx)

    assert "WARNING" in session.blocks[1].output
    assert "conn.interactive()" in session.blocks[1].output
```

---

## Run Unit Tests

```bash
cd exploit-env
uv run pytest ../tests/unit/test_execution_engine.py -v
```

All tests must pass before proceeding to Step 10.
