# Step 10 — challenge_client.py

**Reference docs:** `docs/mcp-api.md` (section "verify_flag")

**Docker required:** No for unit tests. Yes for integration verification.

---

## What to Build

`exploit-env/mcp_server/challenge_client.py` — an async HTTP client that proxies flag verification requests to challenge-env's REST endpoint.

---

## Interface Contract

```python
async def verify_flag(flag: str, host: str, port: int = 5000) -> dict:
    """
    POST {"flag": flag} to http://<host>:<port>/verify.
    Returns {"ok": True, "correct": bool} on success.
    Returns {"ok": False, "error": str} on network failure or unexpected response.
    """
```

---

## Implementation

Use `httpx.AsyncClient`:

```python
import httpx

async def verify_flag(flag: str, host: str, port: int = 5000) -> dict:
    url = f"http://{host}:{port}/verify"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.post(url, json={"flag": flag})
            response.raise_for_status()
            data = response.json()
            return {"ok": True, "correct": bool(data.get("correct", False))}
    except httpx.ConnectError as e:
        return {"ok": False, "error": f"Cannot connect to flag verifier at {url}: {e}"}
    except httpx.TimeoutException:
        return {"ok": False, "error": f"Timeout connecting to flag verifier at {url}"}
    except Exception as e:
        return {"ok": False, "error": f"Unexpected error verifying flag: {e}"}
```

---

## Unit Tests

Create `tests/unit/test_challenge_client.py`. Use `pytest-mock` to mock `httpx.AsyncClient`.

### Test: returns correct=true on matching flag

```python
async def test_verify_flag_correct(mocker):
    mock_response = mocker.MagicMock()
    mock_response.json.return_value = {"correct": True}
    mock_response.raise_for_status = mocker.MagicMock()

    mocker.patch("httpx.AsyncClient.__aenter__",
                 return_value=mocker.AsyncMock(post=mocker.AsyncMock(return_value=mock_response)))

    from mcp_server.challenge_client import verify_flag
    result = await verify_flag("CTF{test}", "localhost")
    assert result == {"ok": True, "correct": True}
```

### Test: returns correct=false on wrong flag

```python
async def test_verify_flag_incorrect(mocker):
    mock_response = mocker.MagicMock()
    mock_response.json.return_value = {"correct": False}
    mock_response.raise_for_status = mocker.MagicMock()
    # ... mock setup ...
    result = await verify_flag("wrong_flag", "localhost")
    assert result == {"ok": True, "correct": False}
```

### Test: returns ok=false on connection error

```python
async def test_verify_flag_connection_error(mocker):
    mocker.patch("httpx.AsyncClient.__aenter__",
                 side_effect=httpx.ConnectError("refused"))
    from mcp_server.challenge_client import verify_flag
    result = await verify_flag("flag", "localhost")
    assert result["ok"] is False
    assert "connect" in result["error"].lower()
```

---

## Run Unit Tests

```bash
cd exploit-env
uv run pytest ../tests/unit/test_challenge_client.py -v
```

All tests must pass before proceeding to Step 11.
