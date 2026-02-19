# Step 04 — proc_utils.py

**Reference docs:** None additional — all specification is in this document.

**Docker required:** No for unit tests. Yes for manual /proc verification.

---

## What to Build

`exploit-env/mcp_server/proc_utils.py` — utilities for scanning `/proc`, discovering challenge child PIDs, and cleaning up processes. This module has no dependencies on other mcp_server modules. It is the foundation that `session.py` depends on.

---

## Interface Contract

This is the public interface that other modules will import. Implement exactly these signatures:

```python
def find_challenge_children(binary_name: str) -> list[dict]:
    """
    Scan /proc for all running processes whose executable name matches
    binary_name (basename only, not full path).

    Returns a list of dicts, one per matching process:
    [
        {
            "pid": int,
            "start_time": int,   # from /proc/<pid>/stat field 22 (jiffies since boot)
            "exe": str,          # resolved symlink of /proc/<pid>/exe
        },
        ...
    ]
    Returns empty list if no matches found.
    Does NOT raise on permission errors or on PIDs that vanish during scan.
    """

def kill_challenge_children(binary_name: str) -> int:
    """
    Send SIGKILL to all processes matching binary_name, then wait for
    them to exit (poll /proc until gone, with a 5-second timeout).

    Returns the number of processes killed.
    Does NOT raise if no matching processes exist.
    Does NOT raise if a process exits before SIGKILL is delivered.
    """

def get_newest_child(binary_name: str) -> int | None:
    """
    Return the PID of the most recently started process matching binary_name,
    identified by the largest start_time value from find_challenge_children().

    Returns None if no matching process exists.
    """

def is_pid_alive(pid: int) -> bool:
    """
    Return True if /proc/<pid> exists, False otherwise.
    Does NOT check whether the process is a zombie.
    """
```

---

## Implementation Notes

### Scanning /proc
Iterate over `/proc` entries. For each numeric directory:
1. Read `/proc/<pid>/exe` as a symlink — use `os.readlink()`. Skip on `PermissionError` or `FileNotFoundError`.
2. Compare `os.path.basename(exe)` to `binary_name`.
3. Read `/proc/<pid>/stat` to get start_time — it is field index 21 (0-based) in the space-separated content, but the process name (field 1) may contain spaces and is wrapped in parentheses. Parse carefully:
   ```python
   with open(f"/proc/{pid}/stat") as f:
       content = f.read()
   # Find the last ')' to skip the process name field
   after_name = content[content.rfind(')') + 2:]
   fields = after_name.split()
   start_time = int(fields[19])   # field 22 overall = index 19 after name
   ```

### kill_challenge_children polling loop
```python
import os, signal, time

pids = [p["pid"] for p in find_challenge_children(binary_name)]
for pid in pids:
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass

deadline = time.time() + 5.0
for pid in pids:
    while time.time() < deadline:
        if not is_pid_alive(pid):
            break
        time.sleep(0.05)
```

---

## Unit Tests

Create `tests/unit/test_proc_utils.py`.

**No Docker required.** Mock all `/proc` filesystem access using `pytest-mock`.

### Test: `find_challenge_children` returns matching processes

```python
def test_find_children_returns_matches(tmp_path, mocker):
    # Create fake /proc structure
    proc_dir = tmp_path / "proc"
    pid_dir = proc_dir / "1234"
    pid_dir.mkdir(parents=True)

    # Mock os.listdir to return ["1234", "self", "version"]
    mocker.patch("os.listdir", return_value=["1234", "self", "version"])

    # Mock os.readlink to return binary path
    mocker.patch("os.readlink", return_value="/challenge/pwn_binary")

    # Mock open for /proc/1234/stat
    stat_content = "1234 (pwn_binary) S 1 1234 1234 0 -1 4194304 " + " ".join(["0"] * 30)
    # Set start_time at field index 19 after name
    fields_after_name = ["S", "1", "1234", "1234", "0", "-1", "4194304"] + ["0"] * 13 + ["99999"] + ["0"] * 10
    stat_content = f"1234 (pwn_binary) {' '.join(fields_after_name)}"
    mocker.patch("builtins.open", mocker.mock_open(read_data=stat_content))

    from mcp_server.proc_utils import find_challenge_children
    # Patch PROC_DIR constant if used
    mocker.patch("mcp_server.proc_utils.PROC_DIR", str(proc_dir))

    result = find_challenge_children("pwn_binary")
    assert len(result) == 1
    assert result[0]["pid"] == 1234
```

### Test: `find_challenge_children` skips non-numeric entries

```python
def test_find_children_skips_non_numeric(mocker):
    mocker.patch("os.listdir", return_value=["self", "version", "cpuinfo"])
    from mcp_server.proc_utils import find_challenge_children
    result = find_challenge_children("pwn_binary")
    assert result == []
```

### Test: `find_challenge_children` handles PermissionError gracefully

```python
def test_find_children_handles_permission_error(mocker):
    mocker.patch("os.listdir", return_value=["1234"])
    mocker.patch("os.readlink", side_effect=PermissionError)
    from mcp_server.proc_utils import find_challenge_children
    result = find_challenge_children("pwn_binary")
    assert result == []
```

### Test: `is_pid_alive` returns True when /proc/<pid> exists

```python
def test_is_pid_alive_true(mocker):
    mocker.patch("os.path.exists", return_value=True)
    from mcp_server.proc_utils import is_pid_alive
    assert is_pid_alive(1234) is True
```

### Test: `is_pid_alive` returns False when /proc/<pid> missing

```python
def test_is_pid_alive_false(mocker):
    mocker.patch("os.path.exists", return_value=False)
    from mcp_server.proc_utils import is_pid_alive
    assert is_pid_alive(9999) is False
```

### Test: `get_newest_child` returns PID with largest start_time

```python
def test_get_newest_child(mocker):
    mocker.patch(
        "mcp_server.proc_utils.find_challenge_children",
        return_value=[
            {"pid": 100, "start_time": 1000, "exe": "/challenge/pwn_binary"},
            {"pid": 200, "start_time": 5000, "exe": "/challenge/pwn_binary"},
            {"pid": 150, "start_time": 3000, "exe": "/challenge/pwn_binary"},
        ]
    )
    from mcp_server.proc_utils import get_newest_child
    assert get_newest_child("pwn_binary") == 200
```

### Test: `get_newest_child` returns None when no children

```python
def test_get_newest_child_none(mocker):
    mocker.patch("mcp_server.proc_utils.find_challenge_children", return_value=[])
    from mcp_server.proc_utils import get_newest_child
    assert get_newest_child("pwn_binary") is None
```

### Test: `kill_challenge_children` returns 0 when none found

```python
def test_kill_no_children(mocker):
    mocker.patch("mcp_server.proc_utils.find_challenge_children", return_value=[])
    from mcp_server.proc_utils import kill_challenge_children
    assert kill_challenge_children("pwn_binary") == 0
```

---

## Run Unit Tests

```bash
cd exploit-env
uv run pytest ../tests/unit/test_proc_utils.py -v
```

All tests must pass before proceeding to Step 05.
