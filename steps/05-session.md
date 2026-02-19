# Step 05 — session.py

**Reference docs:** Read `docs/session-model.md` fully before starting. This step implements exactly what that document specifies.

**Docker required:** No for unit tests.

---

## What to Build

`exploit-env/mcp_server/session.py` — the PwnSession dataclass, the global session singleton, Block 0 initialization, and the reset sequence. This module does NOT execute blocks — that is the execution engine's job. Its responsibility is state management and the reset lifecycle.

---

## Interface Contract

```python
# Module-level global
_session: PwnSession | None = None

def get_session() -> PwnSession | None:
    """Return the current session, or None if no session exists."""

def create_session(challenge_host: str, challenge_port: int) -> PwnSession:
    """
    Create a new session, tearing down any existing one.
    Initializes Block 0 and executes it (establishing conn and pid).
    Returns the fully initialized session with frontier=0.
    Raises RuntimeError if Block 0 execution fails (connection refused, no child found, etc.).
    """

def reset(session: PwnSession) -> None:
    """
    Execute the full reset sequence as specified in docs/session-model.md.
    After this call, session.frontier == 0 and Block 0 has been re-executed.
    Raises RuntimeError if Block 0 re-execution fails.
    Modifies session in-place.
    """

def check_liveness(session: PwnSession) -> tuple[bool, str]:
    """
    Check whether the session's live state (conn + pid) is valid.
    Returns (True, "") if valid.
    Returns (False, error_message) if invalid.
    Does not modify session state.
    """

def to_dict(session: PwnSession) -> dict:
    """
    Serialize the full session state to a JSON-compatible dict.
    Used by the get_session MCP tool.
    """
```

---

## Dataclass Definitions

```python
from dataclasses import dataclass, field
from typing import Literal, Any
import uuid

@dataclass
class Block:
    block_id: str
    index: int
    type: Literal["exploit", "gdb"]
    source: str
    status: Literal["pending", "running", "done", "error"] = "pending"
    output: str = ""

@dataclass
class PwnSession:
    challenge_host: str
    challenge_port: int
    blocks: list[Block] = field(default_factory=list)
    frontier: int = -1
    interpreter: Any = None      # PersistentInterpreter; injected after interpreter.py is built
    conn: Any = None             # pwntools remote
    gdb: Any = None              # GdbController
    pid: int | None = None
    final_flag: str | None = None
```

---

## Block 0 Source String

The displayed source for Block 0 (shown to the Agent read-only):

```python
BLOCK_0_SOURCE = (
    "conn = remote(CHALLENGE_HOST, CHALLENGE_PORT)\n"
    "pid  = <acquired by framework after connection is established>"
)
```

---

## Block 0 Execution (within reset)

Block 0 is not run through the interpreter. Instead, session.py performs these steps directly when executing Block 0 as part of the reset sequence:

```python
from pwn import remote as pwntools_remote
import os

# Step 7 of reset sequence
session.blocks[0].status = "running"
try:
    conn = pwntools_remote(session.challenge_host, session.challenge_port)
    pid = proc_utils.get_newest_child(os.path.basename(CHALLENGE_BINARY))
    if pid is None:
        raise RuntimeError(
            f"No challenge process found after connecting to "
            f"{session.challenge_host}:{session.challenge_port}. "
            f"Is challenge-env running and the binary named correctly?"
        )
    session.conn = conn
    session.pid = pid
    session.interpreter.inject({"conn": conn, "pid": pid})
    session.blocks[0].status = "done"
    session.frontier = 0
except Exception as e:
    session.blocks[0].status = "error"
    session.blocks[0].output = str(e)
    raise RuntimeError(f"Block 0 execution failed: {e}") from e
```

---

## CHALLENGE_BINARY Constant

Define at module level:

```python
import os
CHALLENGE_BINARY = os.environ.get("CHALLENGE_BINARY", "/challenge/pwn_binary")
```

---

## to_dict Serialization

```python
def to_dict(session: PwnSession) -> dict:
    return {
        "challenge_host": session.challenge_host,
        "challenge_port": session.challenge_port,
        "frontier": session.frontier,
        "pid": session.pid,
        "final_flag": session.final_flag,
        "blocks": [
            {
                "block_id": b.block_id,
                "index": b.index,
                "type": b.type,
                "source": b.source,
                "status": b.status,
                "output": b.output,
            }
            for b in session.blocks
        ],
    }
```

---

## Interpreter Dependency

At this step, `session.py` imports from `interpreter.py`, which does not exist yet. Handle this with a forward-compatible import and a stub:

In `session.py`:
```python
try:
    from mcp_server.interpreter import PersistentInterpreter
except ImportError:
    PersistentInterpreter = None   # will be resolved in Step 06
```

The `create_session` and `reset` functions will need to create a `PersistentInterpreter` instance. For now, create it but catch `ImportError` and use `None`. Unit tests for this step mock the interpreter.

---

## Unit Tests

Create `tests/unit/test_session.py`.

Mock `proc_utils`, `PersistentInterpreter`, and `pwntools_remote` in all tests.

### Test: create_session initializes Block 0

```python
def test_create_session_initializes_block_0(mocker):
    mock_conn = mocker.MagicMock()
    mocker.patch("mcp_server.session.pwntools_remote", return_value=mock_conn)
    mocker.patch("mcp_server.proc_utils.get_newest_child", return_value=1234)
    mocker.patch("mcp_server.proc_utils.kill_challenge_children", return_value=0)
    mock_interp = mocker.MagicMock()
    mocker.patch("mcp_server.session.PersistentInterpreter", return_value=mock_interp)

    from mcp_server.session import create_session
    session = create_session("localhost", 4444)

    assert session.frontier == 0
    assert session.pid == 1234
    assert session.conn is mock_conn
    assert session.blocks[0].status == "done"
    assert len(session.blocks) == 1
```

### Test: reset kills gdb before closing conn

```python
def test_reset_kills_gdb_first(mocker):
    from mcp_server.session import PwnSession, Block, BLOCK_0_SOURCE
    mock_gdb = mocker.MagicMock()
    mock_conn = mocker.MagicMock()
    mock_interp = mocker.MagicMock()
    call_order = []
    mock_gdb.kill.side_effect = lambda: call_order.append("gdb_killed")
    mock_conn.close.side_effect = lambda: call_order.append("conn_closed")

    session = PwnSession(
        challenge_host="localhost", challenge_port=4444,
        blocks=[Block("b0", 0, "exploit", BLOCK_0_SOURCE, "done")],
        frontier=2, gdb=mock_gdb, conn=mock_conn, interpreter=mock_interp,
    )

    mocker.patch("mcp_server.session.pwntools_remote", return_value=mocker.MagicMock())
    mocker.patch("mcp_server.proc_utils.get_newest_child", return_value=9999)
    mocker.patch("mcp_server.proc_utils.kill_challenge_children", return_value=0)

    from mcp_server.session import reset
    reset(session)

    assert call_order[0] == "gdb_killed"
    assert call_order[1] == "conn_closed"
```

### Test: reset sets frontier to 0 and clears final_flag

```python
def test_reset_clears_state(mocker):
    # ... setup session with frontier=3, final_flag="CTF{...}"
    # ... mock dependencies
    from mcp_server.session import reset
    reset(session)
    assert session.frontier == 0
    assert session.final_flag is None
    assert session.pid == 9999
```

### Test: reset marks non-Block-0 blocks as pending

```python
def test_reset_marks_blocks_pending(mocker):
    # ... session with blocks at index 0,1,2 all "done"
    from mcp_server.session import reset
    reset(session)
    assert session.blocks[0].status == "done"   # Block 0 re-executed
    assert session.blocks[1].status == "pending"
    assert session.blocks[2].status == "pending"
```

### Test: check_liveness returns False when pid dead

```python
def test_check_liveness_dead_pid(mocker):
    mocker.patch("mcp_server.proc_utils.is_pid_alive", return_value=False)
    from mcp_server.session import PwnSession, Block, check_liveness, BLOCK_0_SOURCE
    session = PwnSession(
        challenge_host="localhost", challenge_port=4444,
        blocks=[Block("b0", 0, "exploit", BLOCK_0_SOURCE)],
        pid=1234, conn=mocker.MagicMock(),
    )
    ok, msg = check_liveness(session)
    assert ok is False
    assert "1234" in msg
```

### Test: to_dict serializes correctly

```python
def test_to_dict(mocker):
    from mcp_server.session import PwnSession, Block, to_dict, BLOCK_0_SOURCE
    session = PwnSession(
        challenge_host="localhost", challenge_port=4444,
        blocks=[Block("b0", 0, "exploit", BLOCK_0_SOURCE, "done")],
        frontier=0, pid=1234, final_flag="CTF{test}",
    )
    d = to_dict(session)
    assert d["frontier"] == 0
    assert d["pid"] == 1234
    assert d["final_flag"] == "CTF{test}"
    assert d["blocks"][0]["block_id"] == "b0"
```

---

## Run Unit Tests

```bash
cd exploit-env
uv run pytest ../tests/unit/test_session.py -v
```

All tests must pass before proceeding to Step 06.
