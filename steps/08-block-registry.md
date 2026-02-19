# Step 08 — block_registry.py

**Reference docs:** `docs/session-model.md` (section "The Frontier"), `docs/mcp-api.md` (section "Block Registry Tools")

**Docker required:** No for unit tests.

---

## What to Build

`exploit-env/mcp_server/block_registry.py` — all block CRUD operations with frontier-aware reset triggering. This module coordinates between the session state and the reset sequence.

---

## Interface Contract

```python
def add_block(session: PwnSession, index: int, type: str, source: str) -> dict:
    """
    Insert a new block at the given index (1-based; cannot insert at 0).
    Shifts existing blocks at index and beyond down by one.
    If the insertion index <= session.frontier: trigger reset, then insert.
    Returns: {
        "block_id": str,
        "index": int,
        "reset_triggered": bool,
        "reset_message": str | None,
    }
    Raises ValueError for invalid index, type, or empty source.
    Raises RuntimeError if reset fails.
    """

def delete_block(session: PwnSession, block_id: str) -> dict:
    """
    Remove the block with the given block_id.
    If block_id is Block 0's ID: raise ValueError("Cannot delete Block 0").
    If the deleted block's index <= session.frontier: trigger reset.
    Reassigns index values of all remaining blocks after deletion.
    Returns: {
        "deleted_index": int,
        "reset_triggered": bool,
        "reset_message": str | None,
    }
    Raises ValueError if block_id not found.
    """

def modify_block(session: PwnSession, block_id: str, source: str) -> dict:
    """
    Replace the source of the given block.
    If block_id is Block 0's ID: raise ValueError("Cannot modify Block 0").
    If the modified block's index <= session.frontier: trigger reset.
    Returns: {
        "block_id": str,
        "index": int,
        "reset_triggered": bool,
        "reset_message": str | None,
    }
    Raises ValueError if block_id not found or source is empty.
    """

def move_block(session: PwnSession, block_id: str, new_index: int) -> dict:
    """
    Move the block to a new position.
    If block_id is Block 0's ID: raise ValueError("Cannot move Block 0").
    If new_index == 0: raise ValueError("Cannot move a block to index 0").
    Reset is triggered if EITHER the source index OR the destination index
    is <= session.frontier.
    Reassigns all index values after the move.
    Returns: {
        "block_id": str,
        "old_index": int,
        "new_index": int,
        "reset_triggered": bool,
        "reset_message": str | None,
    }
    Raises ValueError if block_id not found or new_index out of range.
    """
```

---

## Implementation Notes

### Block 0 identification

Block 0 is always `session.blocks[0]`. Its `block_id` is the stable identifier. Never compare by index alone — always look up by `block_id` to determine if an operation targets Block 0:

```python
def _is_block_0(session: PwnSession, block_id: str) -> bool:
    return session.blocks[0].block_id == block_id
```

### Finding a block by block_id

```python
def _find_block(session: PwnSession, block_id: str) -> tuple[int, Block]:
    """Returns (list_position, block) or raises ValueError."""
    for i, block in enumerate(session.blocks):
        if block.block_id == block_id:
            return i, block
    raise ValueError(f"Block not found: {block_id}")
```

### Index reassignment after insert/delete/move

After any structural change, reassign `block.index` for all blocks so they match their position in the list:

```python
def _reindex(session: PwnSession) -> None:
    for i, block in enumerate(session.blocks):
        block.index = i
```

### Reset trigger logic

```python
def _maybe_reset(session: PwnSession, affected_index: int) -> tuple[bool, str | None]:
    """
    If affected_index <= session.frontier, trigger reset and return (True, message).
    Otherwise return (False, None).
    """
    if affected_index <= session.frontier:
        msg = (
            f"Block at index {affected_index} was modified, which is at or before "
            f"the current frontier ({session.frontier}). Session has been reset."
        )
        from mcp_server.session import reset
        reset(session)
        return True, msg
    return False, None
```

### add_block index validation

```python
def add_block(session, index, type, source):
    if index < 1:
        raise ValueError(f"index must be >= 1, got {index}")
    if index > len(session.blocks):
        raise ValueError(f"index {index} out of range (max: {len(session.blocks)})")
    if type not in ("exploit", "gdb"):
        raise ValueError(f"type must be 'exploit' or 'gdb', got '{type}'")
    if not source.strip():
        raise ValueError("source must not be empty")
    ...
```

For move_block, `new_index` must be ≥ 1 and ≤ `len(session.blocks) - 1`.

---

## Unit Tests

Create `tests/unit/test_block_registry.py`.

Mock `session.reset` in all tests — do not trigger actual resets.

### Test: add_block inserts at correct position

```python
def test_add_block_inserts_correctly(mocker):
    session = make_test_session(mocker, num_blocks=3)  # blocks at 0,1,2
    mocker.patch("mcp_server.session.reset")

    from mcp_server.block_registry import add_block
    result = add_block(session, 2, "exploit", "print('hello')")

    assert len(session.blocks) == 4
    assert session.blocks[2].source == "print('hello')"
    assert session.blocks[2].index == 2
    assert session.blocks[3].index == 3   # shifted
```

### Test: add_block triggers reset when index <= frontier

```python
def test_add_block_triggers_reset(mocker):
    session = make_test_session(mocker, num_blocks=3, frontier=2)
    mock_reset = mocker.patch("mcp_server.session.reset")

    from mcp_server.block_registry import add_block
    result = add_block(session, 1, "exploit", "x = 1")

    mock_reset.assert_called_once_with(session)
    assert result["reset_triggered"] is True
```

### Test: add_block does not reset when index > frontier

```python
def test_add_block_no_reset_after_frontier(mocker):
    session = make_test_session(mocker, num_blocks=3, frontier=1)
    mock_reset = mocker.patch("mcp_server.session.reset")

    from mcp_server.block_registry import add_block
    result = add_block(session, 3, "gdb", "info registers")

    mock_reset.assert_not_called()
    assert result["reset_triggered"] is False
```

### Test: delete_block rejects Block 0

```python
def test_delete_block_0_rejected(mocker):
    session = make_test_session(mocker, num_blocks=2)
    import pytest
    from mcp_server.block_registry import delete_block
    with pytest.raises(ValueError, match="Cannot delete Block 0"):
        delete_block(session, session.blocks[0].block_id)
```

### Test: modify_block rejects Block 0

```python
def test_modify_block_0_rejected(mocker):
    session = make_test_session(mocker, num_blocks=1)
    import pytest
    from mcp_server.block_registry import modify_block
    with pytest.raises(ValueError, match="Cannot modify Block 0"):
        modify_block(session, session.blocks[0].block_id, "conn.close()")
```

### Test: move_block triggers reset if source OR destination <= frontier

```python
def test_move_triggers_reset_if_dest_at_frontier(mocker):
    session = make_test_session(mocker, num_blocks=4, frontier=2)
    mock_reset = mocker.patch("mcp_server.session.reset")

    from mcp_server.block_registry import move_block
    # Move block at index 3 (> frontier) to index 2 (== frontier)
    result = move_block(session, session.blocks[3].block_id, 2)

    mock_reset.assert_called_once()
    assert result["reset_triggered"] is True
```

### Test: reindex reassigns all indices after insert

```python
def test_reindex_after_insert(mocker):
    session = make_test_session(mocker, num_blocks=3)
    mocker.patch("mcp_server.session.reset")

    from mcp_server.block_registry import add_block
    add_block(session, 1, "exploit", "x = 1")

    for i, block in enumerate(session.blocks):
        assert block.index == i, f"Block at list position {i} has index {block.index}"
```

### Helper for tests

```python
def make_test_session(mocker, num_blocks=1, frontier=0):
    """Create a PwnSession with num_blocks blocks and given frontier."""
    import uuid
    from mcp_server.session import PwnSession, Block, BLOCK_0_SOURCE
    blocks = [Block(str(uuid.uuid4()), i, "exploit",
                    BLOCK_0_SOURCE if i == 0 else f"# block {i}",
                    "done" if i <= frontier else "pending")
              for i in range(num_blocks)]
    return PwnSession(
        challenge_host="localhost",
        challenge_port=4444,
        blocks=blocks,
        frontier=frontier,
        interpreter=mocker.MagicMock(),
        conn=mocker.MagicMock(),
    )
```

---

## Run Unit Tests

```bash
cd exploit-env
uv run pytest ../tests/unit/test_block_registry.py -v
```

All tests must pass before proceeding to Step 09.
