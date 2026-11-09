# Setup

**Python 3.13.2** (pinned in `.python-version`). Check with `python --version` inside the venv. Clone outside OneDrive or other synced folders, because DuckDB files and `.venv` can clash with syncing.

Install Python 3.13.2 if you don't have it:
- Windows: installer from https://www.python.org/downloads/release/python-3132/ (then `py -3.13` works).
- macOS: installer from the same page, or `uv python install 3.13.2`.

Windows (PowerShell):

```powershell
py -3.13 -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
copy .env.example .env   # then add the LLM key (LLM_API_KEY)
```

macOS / Linux:

```bash
python3.13 -m venv .venv          # or: uv venv --python 3.13.2
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env              # then add the LLM key (LLM_API_KEY)
```

If you already have a `.venv` built with another version, delete it and create it again.

## LLM

The triage model is `ornith` on the hackathon's UAB DCC GPU gateway (OpenAI-compatible), and `triage/llm.py` refuses any other endpoint. Nothing to install beyond `requirements.txt`. Put the organizers' key in `.env` (never in code, commands or chat):

```env
LLM_PROVIDER=openai_compatible
LLM_BASE_URL=https://dcc-llm-gw.uab.cat/uabthehack/v1
LLM_MODEL=ornith
LLM_API_KEY=<key from the organizers>
```

Optional settings (defaults in brackets): `LLM_THINKING` [off] (on = the model's reasoning phase; ~10x slower and it truncates with the C2 prompt), `LLM_MAX_OUTPUT_TOKENS` [4096], `LLM_TIMEOUT_S` [120; the SDK retries a timeout twice], `LLM_CACHE_DIR` [.cache], `LLM_DISABLE_CACHE=1` (always call the API), `LLM_OFFLINE=1` (replay from the cache only).


Check it works (one real call, then a cache hit):

```powershell
python -m triage.llm
```

If it fails with `auth_failed`, the key is wrong or disabled; `endpoint_not_allowed` means `LLM_BASE_URL` isn't the gateway; `rate_limited` or `server_unavailable` are on the gateway's side.

> **Without the gateway.** The gateway was provided for the hackathon (6–8 Nov 2026) and may no longer answer. Everything except triaging new alerts still works without it: the console reads the committed results in `out/`, the evaluation scores them, and the tests replace the LLM with fakes (they pass with the gateway blocked and an empty cache). `LLM_OFFLINE=1` replays answers from a local cache, which is not part of the repository. To use another OpenAI-compatible endpoint, add its host to `ALLOWED_HOSTS` in `triage/llm.py` and set `LLM_BASE_URL` and `LLM_MODEL`; the model must support strict JSON-schema output.

## Database, API and tests

The data in `01_contexto/` … `05_inteligencia/` is an invented week at Tarvia in the same format as the organizers' dataset, which is private (see [the data](../README.md#the-data)). To regenerate it after changing the generator, run `python tools/make_mock_data.py`; if the row counts change, update `LOG_SOURCES` and `EXPECTED_ALERTS` in `triage/loader.py`.

Build the database (about a second; rerun after regenerating the data or pulling loader changes, with the API and UI stopped):

```powershell
python -m triage.loader
```

Start the fast SOC API from the repo root, with docs on http://localhost:8000/docs. It has the same contract as the organizers' mock SOC API, plus extra read endpoints:

```powershell
uvicorn api.soc_api:app --port 8000
```

Run the tests:

```powershell
python -m pytest tests
```

Python code can skip HTTP and use `triage/data.py` directly (`timeline`, `mentions`, `search_logs`, `get_event`, `get_asset`, `get_user`, `get_intel`, `get_sandbox`, `find_changes`, `resolve_ip`, `vpn_session`, `hosts_for_user`, `users_for_host`, `window`).

## Results store

`triage/store.py` is how everything reads and writes results in `out/`: `default_store().save_ticket(...)`, `.load_tickets()`, `.save_incident(...)`, `.record_review(...)`, `.record_action(...)`. Tickets are checked against the official format when saved. Set `stage: "grouped"` on incidents that only have their alerts so far.

To work with the fake tickets in `ui/fixtures/`, set `TARVIA_OUT` to that folder:

```powershell
$env:TARVIA_OUT = "ui/fixtures"
```

## Console

From the repo root, with the venv active. It opens on http://localhost:8501 and shows fake tickets until `out/tickets.jsonl` exists. Open it once before a demo, because the first load is slow.

```powershell
streamlit run ui/app.py
```

To approve containment from the ticket page, start the SOC API in a second terminal. Set `SOC_API_URL` if it isn't on port 8000:

```powershell
uvicorn api.soc_api:app --port 8000
```

Clear `out/containment_log.jsonl` and `out/reviews.jsonl` before a demo, so rehearsal actions don't appear in it.
