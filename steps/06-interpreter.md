# Step 06 — interpreter.py

**Reference docs:** `docs/session-model.md` (sections "Exploit Block Execution" and "final_flag Semantics")

**Docker required:** No for unit tests.

---

## What to Build

`exploit-env/mcp_server/interpreter.py` — a persistent Python interpreter that accumulates namespace state across multiple `execute()` calls, pre-imports pwntools, captures stdout/stderr, and supports variable injection.

---

## Interface Contract

```python
class PersistentInterpreter:

    def __init__(self) -> None:
        """
        Initialize a fresh interpreter with an empty namespace,
        then call _setup_namespace() to pre-import pwntools symbols.
        """

    def reset(self) -> None:
        """
        Discard the current namespace entirely and create a fresh one.
        Call _setup_namespace() again on the new namespace.
        Any previously injected variables (conn, pid) are lost.
        """

    def inject(self, variables: dict) -> None:
        """
        Merge the given variables into the current namespace.
        Used by session.py to inject conn and pid after Block 0.
        Example: inject({"conn": <remote object>, "pid": 1234})
        """

    def execute(self, source: str) -> tuple[str, str]:
        """
        Execute source in the current namespace.
        Captures stdout and stderr separately.
        Returns (stdout_output, stderr_output).

        If source contains a syntax error or raises an exception:
            - The exception is NOT re-raised.
            - stderr_output contains the full traceback as a string.
            - Returns ("", traceback_string).

        State changes from partial execution ARE preserved in the namespace
        (consistent with Python's interactive interpreter behavior).
        """

    def get_var(self, name: str) -> Any | None:
        """
        Return the value of a variable in the current namespace,
        or None if it does not exist.
        Used by the execution engine to check final_flag after each exploit block.
        """

    def _setup_namespace(self) -> None:
        """
        Execute standard pwntools imports into the current namespace.
        Called by __init__() and reset().
        """
```

---

## Implementation Notes

### Namespace initialization

```python
import code, io, sys, contextlib
from typing import Any

PWNTOOLS_SETUP = """\
from pwn import *
context.log_level = 'warning'
"""

class PersistentInterpreter:
    def __init__(self):
        self._namespace: dict = {}
        self._setup_namespace()

    def _setup_namespace(self):
        # Execute pwntools imports into the namespace
        exec(compile(PWNTOOLS_SETUP, "<setup>", "exec"), self._namespace)
```

### stdout/stderr capture

Use `contextlib.redirect_stdout` and `contextlib.redirect_stderr` with `io.StringIO`:

```python
def execute(self, source: str) -> tuple[str, str]:
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()
    try:
        compiled = compile(source, "<block>", "exec")
    except SyntaxError as e:
        return "", f"SyntaxError: {e}\n"

    try:
        with contextlib.redirect_stdout(stdout_buf), \
             contextlib.redirect_stderr(stderr_buf):
            exec(compiled, self._namespace)
    except Exception:
        import traceback
        stderr_buf.write(traceback.format_exc())

    return stdout_buf.getvalue(), stderr_buf.getvalue()
```

### Important: pwntools stdout

pwntools writes some output directly to the underlying file descriptor rather than through Python's `sys.stdout`. This means `redirect_stdout` will not capture all pwntools output. This is acceptable — the Agent can still see connection errors through the exception traceback. Do not attempt to capture FD-level output (it would require subprocess-level redirection which is not worth the complexity here).

---

## Unit Tests

Create `tests/unit/test_interpreter.py`.

### Test: variables persist across execute calls

```python
def test_variables_persist():
    from mcp_server.interpreter import PersistentInterpreter
    interp = PersistentInterpreter()
    interp.execute("x = 42")
    interp.execute("y = x + 1")
    assert interp.get_var("y") == 43
```

### Test: stdout is captured

```python
def test_stdout_captured():
    from mcp_server.interpreter import PersistentInterpreter
    interp = PersistentInterpreter()
    stdout, stderr = interp.execute("print('hello world')")
    assert "hello world" in stdout
    assert stderr == ""
```

### Test: exception returns traceback in stderr, does not raise

```python
def test_exception_captured():
    from mcp_server.interpreter import PersistentInterpreter
    interp = PersistentInterpreter()
    stdout, stderr = interp.execute("raise ValueError('test error')")
    assert stdout == ""
    assert "ValueError" in stderr
    assert "test error" in stderr
```

### Test: syntax error returns error string, does not raise

```python
def test_syntax_error_captured():
    from mcp_server.interpreter import PersistentInterpreter
    interp = PersistentInterpreter()
    stdout, stderr = interp.execute("def bad(:\n    pass")
    assert "SyntaxError" in stderr
```

### Test: inject makes variables available in execute

```python
def test_inject_available_in_execute():
    from mcp_server.interpreter import PersistentInterpreter
    interp = PersistentInterpreter()
    interp.inject({"my_pid": 9999})
    stdout, _ = interp.execute("print(my_pid)")
    assert "9999" in stdout
```

### Test: reset clears namespace

```python
def test_reset_clears_namespace():
    from mcp_server.interpreter import PersistentInterpreter
    interp = PersistentInterpreter()
    interp.execute("secret = 'hidden'")
    interp.reset()
    assert interp.get_var("secret") is None
```

### Test: pwntools symbols available after init

```python
def test_pwntools_preloaded():
    from mcp_server.interpreter import PersistentInterpreter
    interp = PersistentInterpreter()
    stdout, stderr = interp.execute("print(p64(0x41414141))")
    assert stderr == ""
    assert stdout.strip() != ""
```

### Test: get_var returns None for missing variable

```python
def test_get_var_missing():
    from mcp_server.interpreter import PersistentInterpreter
    interp = PersistentInterpreter()
    assert interp.get_var("nonexistent") is None
```

### Test: partial execution preserves state before exception

```python
def test_partial_execution_preserves_state():
    from mcp_server.interpreter import PersistentInterpreter
    interp = PersistentInterpreter()
    interp.execute("a = 1\nb = 2\nraise Exception('stop')\nc = 3")
    # a and b should be set, c should not
    assert interp.get_var("a") == 1
    assert interp.get_var("b") == 2
    # c may or may not be set depending on execution point; this is acceptable
```

---

## Run Unit Tests

```bash
cd exploit-env
uv run pytest ../tests/unit/test_interpreter.py -v
```

All tests must pass before proceeding to Step 07.
