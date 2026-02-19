# Step 11 — ghidra_proxy.py

**Reference docs:** `docs/mcp-api.md` (section "Reverse Engineering Tools")

**Docker required:** No for unit tests. Yes for integration verification.

---

## What to Build

`exploit-env/mcp_server/ghidra_proxy.py` — an async HTTP client that forwards reverse engineering requests to the pyghidra-mcp container and normalizes responses for the MCP tool layer.

---

## Interface Contract

```python
PYGHIDRA_MCP_URL = os.environ.get("PYGHIDRA_MCP_URL", "http://pyghidra-mcp:9090")

async def analyze_binary(binary_path: str) -> dict:
    """
    Request Ghidra analysis of the binary at binary_path.
    Returns {"ok": True, "functions": [...], "imports": [...], "strings": [...]}
    or {"ok": False, "error": str}.
    """

async def decompile_function(name_or_addr: str) -> dict:
    """
    Request decompilation of the function identified by name or hex address.
    Returns {"ok": True, "name": str, "address": str, "source": str}
    or {"ok": False, "error": str}.
    """

async def get_xrefs(addr: str) -> dict:
    """
    Request cross-references for the given address.
    Returns {"ok": True, "addr": str, "refs_to": [...], "refs_from": [...]}
    or {"ok": False, "error": str}.
    """
```

---

## Implementation Notes

The exact HTTP API of pyghidra-mcp depends on the upstream image. Before implementing, inspect the pyghidra-mcp documentation or running container to determine endpoint paths and request/response shapes. The normalization layer in this module adapts whatever pyghidra-mcp returns into the shapes defined in `docs/mcp-api.md`.

If pyghidra-mcp exposes an MCP-compatible interface rather than plain HTTP, use the MCP Python SDK client instead of httpx. Check the upstream image documentation to determine which approach is required.

General pattern using httpx:

```python
import httpx, os

PYGHIDRA_MCP_URL = os.environ.get("PYGHIDRA_MCP_URL", "http://pyghidra-mcp:9090")

async def _post(endpoint: str, payload: dict) -> dict:
    url = f"{PYGHIDRA_MCP_URL}{endpoint}"
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.post(url, json=payload)
            response.raise_for_status()
            return {"ok": True, "data": response.json()}
    except httpx.ConnectError:
        return {"ok": False, "error": f"Cannot connect to pyghidra-mcp at {PYGHIDRA_MCP_URL}"}
    except httpx.TimeoutException:
        return {"ok": False, "error": "pyghidra-mcp request timed out (analysis may take time)"}
    except Exception as e:
        return {"ok": False, "error": f"pyghidra-mcp error: {e}"}
```

Note: Ghidra analysis can be slow (30–120 seconds for the first analysis of a binary). The httpx timeout should be set to at least 120 seconds for `analyze_binary`. Use a shorter timeout (10–15 seconds) for `decompile_function` and `get_xrefs` since those operate on already-analyzed projects.

---

## Unit Tests

Create `tests/unit/test_ghidra_proxy.py`. Mock all HTTP calls.

### Test: analyze_binary returns ok=True with mocked response

```python
async def test_analyze_binary_success(mocker):
    mock_data = {
        "functions": [{"name": "main", "address": "0x401234"}],
        "imports": ["puts"],
        "strings": ["hello"],
    }
    # mock _post to return {"ok": True, "data": mock_data}
    mocker.patch("mcp_server.ghidra_proxy._post",
                 return_value={"ok": True, "data": mock_data})

    from mcp_server.ghidra_proxy import analyze_binary
    result = await analyze_binary("/challenges/example-bof/pwn_binary")
    assert result["ok"] is True
    assert "functions" in result
```

### Test: decompile_function returns ok=False on connection error

```python
async def test_decompile_connection_error(mocker):
    mocker.patch("mcp_server.ghidra_proxy._post",
                 return_value={"ok": False, "error": "Cannot connect"})

    from mcp_server.ghidra_proxy import decompile_function
    result = await decompile_function("main")
    assert result["ok"] is False
    assert "connect" in result["error"].lower()
```

---

## Run Unit Tests

```bash
cd exploit-env
uv run pytest ../tests/unit/test_ghidra_proxy.py -v
```

All tests must pass before proceeding to Step 12.
