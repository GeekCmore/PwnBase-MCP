# Step 07 — gdb_controller.py

**Reference docs:** `docs/session-model.md` (section "GDB Block Execution")

**Docker required:** No for unit tests. Yes for manual GDB verification.

---

## What to Build

`exploit-env/mcp_server/gdb_controller.py` — manages the lifecycle of a pwndbg subprocess: attach, execute commands, capture output, detach, and kill.

---

## Interface Contract

```python
class GdbController:

    def __init__(self) -> None:
        """
        Initialize without spawning a process.
        self._process is None until attach() is called.
        """

    def attach(self, pid: int) -> str:
        """
        Spawn a gdb subprocess with pwndbg loaded and attach to the given PID.
        Waits for the GDB prompt to confirm attachment.
        Returns the initial output (banner + attach confirmation).
        Raises RuntimeError if gdb process fails to start or attach fails.
        """

    def execute_commands(self, commands: list[str]) -> str:
        """
        Execute a list of GDB commands sequentially.
        Waits for the GDB prompt after each command before sending the next.
        Returns all captured output concatenated as a single string.
        Raises RuntimeError if the process is not attached.
        """

    def detach(self) -> None:
        """
        Send 'detach' then 'quit' to gdb.
        Wait for the process to exit cleanly (timeout: 5 seconds).
        If it does not exit, kill it.
        Sets self._process = None.
        """

    def kill(self) -> None:
        """
        Forcibly terminate the gdb process (SIGKILL).
        Does nothing if process is not running.
        Sets self._process = None.
        """

    @property
    def is_attached(self) -> bool:
        """Return True if a gdb process is currently running."""
```

---

## Implementation Notes

### Spawning pwndbg

```python
import subprocess, os

GDB_COMMAND = ["gdb", "-q", "--nx"]
# pwndbg is installed as a gdb extension via ~/.gdbinit or /etc/gdb/gdbinit.
# The --nx flag skips .gdbinit but pwndbg setup.sh installs to a system path.
# If pwndbg is not loading, try without --nx.
```

Spawn with:
```python
self._process = subprocess.Popen(
    GDB_COMMAND,
    stdin=subprocess.PIPE,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,    # merge stderr into stdout
    text=True,
    bufsize=0,
)
```

### Prompt detection

GDB outputs `(gdb) ` as its prompt. Read output until this prompt appears to know when a command has completed:

```python
PROMPT = "(gdb) "

def _read_until_prompt(self, timeout: float = 30.0) -> str:
    """
    Read from process stdout until the GDB prompt appears.
    Returns all output including the prompt line.
    Raises TimeoutError if prompt not seen within timeout seconds.
    """
    import select, time
    output = ""
    deadline = time.time() + timeout
    while time.time() < deadline:
        ready, _, _ = select.select([self._process.stdout], [], [], 0.1)
        if ready:
            chunk = self._process.stdout.read(4096)
            if not chunk:
                break
            output += chunk
            if PROMPT in output:
                return output
    raise TimeoutError(f"GDB prompt not seen within {timeout}s. Output so far:\n{output}")
```

### attach implementation

```python
def attach(self, pid: int) -> str:
    # Spawn process
    self._process = subprocess.Popen(...)
    # Wait for initial prompt
    initial = self._read_until_prompt()
    # Send attach command
    self._process.stdin.write(f"attach {pid}\n")
    self._process.stdin.flush()
    # Wait for prompt after attach
    attach_output = self._read_until_prompt()
    return initial + attach_output
```

### execute_commands implementation

```python
def execute_commands(self, commands: list[str]) -> str:
    if not self.is_attached:
        raise RuntimeError("GdbController: not attached to any process")
    output = ""
    for cmd in commands:
        self._process.stdin.write(cmd + "\n")
        self._process.stdin.flush()
        output += self._read_until_prompt()
    return output
```

### detach implementation

```python
def detach(self) -> None:
    if self._process is None:
        return
    try:
        self._process.stdin.write("detach\n")
        self._process.stdin.flush()
        self._read_until_prompt(timeout=5.0)
        self._process.stdin.write("quit\n")
        self._process.stdin.flush()
        self._process.wait(timeout=5.0)
    except Exception:
        self.kill()
        return
    self._process = None
```

---

## Unit Tests

Create `tests/unit/test_gdb_controller.py`.

Mock `subprocess.Popen` — do not require an actual GDB binary for unit tests.

### Test: is_attached returns False before attach

```python
def test_not_attached_initially():
    from mcp_server.gdb_controller import GdbController
    gdb = GdbController()
    assert gdb.is_attached is False
```

### Test: attach calls gdb with correct args

```python
def test_attach_spawns_gdb(mocker):
    mock_proc = mocker.MagicMock()
    mock_proc.stdout.read.return_value = "(gdb) "
    mock_popen = mocker.patch("subprocess.Popen", return_value=mock_proc)

    from mcp_server.gdb_controller import GdbController
    gdb = GdbController()
    # Mock _read_until_prompt to avoid actual I/O
    mocker.patch.object(gdb, "_read_until_prompt", return_value="(gdb) ")
    gdb.attach(1234)

    mock_popen.assert_called_once()
    args = mock_popen.call_args[0][0]
    assert "gdb" in args
    # Verify attach command was sent
    mock_proc.stdin.write.assert_any_call("attach 1234\n")
```

### Test: is_attached returns True after attach

```python
def test_is_attached_after_attach(mocker):
    mock_proc = mocker.MagicMock()
    mocker.patch("subprocess.Popen", return_value=mock_proc)
    from mcp_server.gdb_controller import GdbController
    gdb = GdbController()
    mocker.patch.object(gdb, "_read_until_prompt", return_value="(gdb) ")
    gdb.attach(1234)
    assert gdb.is_attached is True
```

### Test: execute_commands raises when not attached

```python
def test_execute_commands_not_attached():
    from mcp_server.gdb_controller import GdbController
    gdb = GdbController()
    with pytest.raises(RuntimeError, match="not attached"):
        gdb.execute_commands(["info registers"])
```

### Test: execute_commands sends each command

```python
def test_execute_commands_sends_each(mocker):
    mock_proc = mocker.MagicMock()
    mocker.patch("subprocess.Popen", return_value=mock_proc)
    from mcp_server.gdb_controller import GdbController
    gdb = GdbController()
    mocker.patch.object(gdb, "_read_until_prompt", return_value="rax 0x1\n(gdb) ")
    gdb._process = mock_proc   # simulate attached state

    gdb.execute_commands(["info registers", "bt"])

    calls = [c[0][0] for c in mock_proc.stdin.write.call_args_list]
    assert "info registers\n" in calls
    assert "bt\n" in calls
```

### Test: kill sets _process to None

```python
def test_kill_clears_process(mocker):
    mock_proc = mocker.MagicMock()
    from mcp_server.gdb_controller import GdbController
    gdb = GdbController()
    gdb._process = mock_proc
    gdb.kill()
    assert gdb._process is None
    mock_proc.kill.assert_called_once()
```

---

## Run Unit Tests

```bash
cd exploit-env
uv run pytest ../tests/unit/test_gdb_controller.py -v
```

All tests must pass before proceeding to Step 08.
