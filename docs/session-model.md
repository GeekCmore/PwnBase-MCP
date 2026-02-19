# Session Model — Full Reference

This is the most important reference document. Read it fully before implementing `session.py`, `block_registry.py`, `execution_engine.py`, or `interpreter.py`. Everything in the execution system derives from the model described here.

---

## Core Concept

The session model is inspired by Jupyter notebooks but adapted for the constraints of binary exploitation:

- **Process state is not reproducible.** A challenge binary that has received a payload cannot be "rewound." Every re-run requires a fresh process.
- **The interpreter state must persist across blocks.** Variables like `conn`, `pid`, and computed addresses must be available in subsequent blocks without re-assignment.
- **Debugging and exploitation are interleaved.** A GDB block can inspect process state between two exploit blocks, but the TCP connection must remain alive throughout.

---

## The One Active Session Rule

There is exactly one `PwnSession` instance at any time, stored as a module-level global in `session.py`. All MCP tools operate on this single session. There is no session ID, no concurrency, no multiplexing. If `new_session()` is called while a session exists, the existing session is torn down first.

---

## PwnSession Fields

```python
@dataclass
class PwnSession:
    challenge_host: str
    challenge_port: int
    blocks: list[Block]          # Always starts with Block 0; never empty
    frontier: int                # Index of last successfully completed block; -1 if nothing run
    interpreter: PersistentInterpreter | None
    conn: Any | None             # pwntools remote object; None after reset, before Block 0
    gdb: GdbController | None    # Active pwndbg instance; None when not attached
    pid: int | None              # PID of current xinetd child; None before Block 0
    final_flag: str | None       # Most recent value of final_flag from interpreter namespace
```

---

## Block Model

```python
@dataclass
class Block:
    block_id: str       # UUID; stable across moves and edits
    index: int          # Current position in ordered list; 0-based
    type: Literal["exploit", "gdb"]
    source: str         # Python code (exploit) or newline-separated GDB commands (gdb)
    status: Literal["pending", "running", "done", "error"]
    output: str         # Captured output from last execution; "" if never run
```

**block_id is the stable identity.** index changes when blocks are moved or when blocks before this one are inserted/deleted. Always look up blocks by block_id internally; use index only for ordering and frontier comparison.

---

## Block 0

Block 0 is special. It is created automatically when a session is initialized and cannot be edited or deleted.

Its conceptual source (shown to the Agent) is:
```python
conn = remote(CHALLENGE_HOST, CHALLENGE_PORT)
pid  = <acquired by framework>
```

**Block 0 is not executed by the normal interpreter.** The framework executes it specially:
1. Calls `pwntools.remote(challenge_host, challenge_port)` directly in Python, not via the interpreter's `exec()`.
2. Waits for the connection to be established (this causes xinetd to fork a child).
3. Calls `proc_utils.get_newest_child(binary_name)` to get the PID of the newly forked child.
4. Injects `conn` and `pid` into the interpreter namespace via `interpreter.inject({"conn": conn, "pid": pid})`.
5. Sets `session.conn = conn`, `session.pid = pid`.
6. Marks Block 0 as `done` and sets `frontier = 0`.

Block 0 is part of the frontier system (index 0). Any edit to blocks with `index <= frontier` triggers a reset, which includes Block 0 — but Block 0 itself is non-editable, so this path is never reached through normal edits. The protection is: reject any edit or delete operation targeting `block_id == session.blocks[0].block_id`.

---

## The Frontier

`frontier` is the index of the last successfully completed block. It starts at `-1` (nothing has run) and advances to `0` after Block 0 completes.

The frontier determines the safety boundary for edits:

```
blocks:   [0]   [1]   [2]   [3]   [4]   [5]
frontier:              ↑ (frontier = 2)
          ←── locked ──→  ←── free to edit ──→
```

- Blocks at index ≤ frontier: edits trigger a full reset.
- Blocks at index > frontier: edits are applied immediately with no side effects.

**Why?** Blocks up to the frontier have been executed; their effects are baked into the interpreter state, the live connection, and the challenge process's memory. Changing any of them would make the current state inconsistent. The only honest response is a full restart.

---

## Reset Sequence

The reset sequence is the atomic operation that tears down all live state and re-establishes a clean starting point. It must be executed:
- When any block edit targets `index <= frontier`
- When `reset_session()` is called explicitly
- At the start of every `run_to()` and `run_all()` call

**The exact sequence (order matters):**

```
1. If session.gdb is not None:
       session.gdb.kill()
       session.gdb = None

2. If session.conn is not None:
       session.conn.close()
       session.conn = None

3. proc_utils.kill_challenge_children(CHALLENGE_BINARY_NAME)
   # Kill ALL existing xinetd children of the challenge binary.
   # This is critical: it guarantees exactly one child exists after step 6.

4. session.interpreter.reset()
   # Tear down interpreter namespace; create fresh one with pwntools pre-imported.

5. For every block in session.blocks where block.block_id != blocks[0].block_id:
       block.status = "pending"
       block.output = ""

6. session.frontier = -1
   session.pid = None
   session.final_flag = None

7. Execute Block 0:
       session.conn = remote(session.challenge_host, session.challenge_port)
       session.pid = proc_utils.get_newest_child(CHALLENGE_BINARY_NAME)
       session.interpreter.inject({"conn": session.conn, "pid": session.pid})
       session.blocks[0].status = "done"
       session.frontier = 0
```

If step 7 fails (connection refused, no child found), the session remains in a broken state. Surface this as an error to the caller with a clear message. Do not silently continue.

---

## Exploit Block Execution

Called by the execution engine for blocks with `type == "exploit"`:

```
1. block.status = "running"

2. output, error = session.interpreter.execute(block.source)
   # Captures stdout/stderr; raises on syntax error.

3. block.output = output + (error if error else "")
   block.status = "done" if no exception else "error"

4. If status == "done":
       flag_value = session.interpreter.get_var("final_flag")
       if flag_value is not None:
           session.final_flag = str(flag_value)

5. Check for terminal operations in block.source:
       terminal_ops = ["conn.interactive()", "conn.recvall()", "conn.close()"]
       for op in terminal_ops:
           if op in block.source:
               block.output += f"\nWARNING: '{op}' is a terminal operation. "
                               f"Subsequent blocks will not be able to use conn."

6. session.frontier = block.index
```

---

## GDB Block Execution

Called by the execution engine for blocks with `type == "gdb"`:

```
1. block.status = "running"

2. If session.gdb is not None:
       session.gdb.kill()
       session.gdb = None

3. session.gdb = GdbController()
   session.gdb.attach(session.pid)

4. commands = [line for line in block.source.splitlines() if line.strip()]
   output = session.gdb.execute_commands(commands)

5. session.gdb.detach()
   session.gdb = None

6. block.output = output
   block.status = "done"

7. session.frontier = block.index
```

`conn` is untouched throughout. The challenge process resumes after `detach()`. TCP buffer state is not inspected.

---

## Liveness Check

Used by `step()` and `continue()` before executing:

```python
def check_liveness(session: PwnSession) -> tuple[bool, str]:
    if session.conn is None:
        return False, "conn is None (session not initialized or reset needed)"
    if session.pid is None:
        return False, "pid is None (session not initialized)"
    if not proc_utils.is_pid_alive(session.pid):
        return False, f"Challenge process (pid={session.pid}) no longer exists. "
                      f"It likely crashed. Use run_to() or run_all() to restart."
    try:
        session.conn.fileno()  # raises if socket is closed
    except Exception:
        return False, "conn is closed. Use run_to() or run_all() to restart."
    return True, ""
```

---

## final_flag Semantics

`final_flag` is extracted from the interpreter namespace after **every exploit block**, not just the last one. The rule is **last assignment wins**: if Block 2 sets `final_flag = "CTF{partial}"` and Block 4 sets `final_flag = "CTF{real}"`, `session.final_flag` will be `"CTF{real}"` after Block 4 runs.

This means:
- The Agent can set `final_flag` in any exploit block.
- The session always reflects the most recent value seen.
- GDB blocks never affect `final_flag`.
- `final_flag` is reset to `None` at the start of every reset sequence.

---

## State Diagram

```
                        new_session()
                             │
                             ▼
                    ┌─── INITIALIZING ───┐
                    │  (Block 0 runs)    │
                    └────────┬───────────┘
                             │ Block 0 done
                             ▼
              ┌──────────── IDLE ◄────────────────┐
              │         (frontier = 0)             │
              │                                    │
    run_to(N) │                           reset()  │
    run_all() │                                    │
    step(N)   │                           edit at  │
    continue()│                           ≤ frontier
              ▼                                    │
          RUNNING ──── error ──► ERROR ────────────┤
              │                                    │
              │ all target blocks done             │
              ▼                                    │
           PAUSED ─── step()/continue() ──► RUNNING
         (frontier=N)      (no reset)
              │
              └── edit at > frontier → stays PAUSED (no reset)
```
