"""Fast SOC API: the organizers' mock API contract, backed by DuckDB, plus extra read endpoints.

Run from the repo root (build the database first with `python -m triage.loader`):
    uvicorn api.soc_api:app --port 8000

Same endpoints and responses as the organizers' mock SOC API (not included in this repository);
tests/test_api.py checks the contract.
Differences: assets add `services`, changes add UTC windows and scope details, users also accept
`TARVIA\\user`, and the containment log is written to `out/` to keep the dataset folder clean.

Containment is deliberately stricter than the mock: triage/policy.py decides what may run, every
action needs a token (D-4, including block_ioc and purge_email), /approvals needs a ticket_id, and a
token works once, for one action, target and ticket, for a few minutes. It is never logged.

Agents must never get /approvals as a tool: it issues a token to any caller, so the human gate
depends on only the UI calling it.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import threading
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel, Field

from triage import data, policy
from triage.loader import LOG_SOURCES, ROOT

LOGFILE = Path(os.environ.get("SOC_CONTAINMENT_LOG", ROOT / "out" / "containment_log.jsonl"))
VALID = {"isolate_host", "disable_user", "revoke_sessions", "reset_password", "block_ioc", "purge_email", "disable_access_key"}
TOKEN_TTL_SECONDS = 300

APPROVALS: dict[str, dict] = {}
_log_lock = threading.Lock()
_approvals_lock = threading.Lock()

app = FastAPI(title="Tarvia SOC (fast, simulated)", version="1.0")


def _parse_or_400(call, *args, **kwargs):
    """Run a query, turning a malformed timestamp or filter into a 400 response."""
    try:
        return call(*args, **kwargs)
    except ValueError as error:
        raise HTTPException(400, str(error)) from error


@app.get("/alerts")
def list_alerts(status: str = "new", desde: str = "", hasta: str = "", rule_id: str = "", limit: int = 50, offset: int = 0):
    return data.list_alerts(status=status, start=desde, end=hasta, rule_id=rule_id, limit=limit, offset=offset)


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: str):
    alert = data.get_alert(alert_id)
    if not alert:
        raise HTTPException(404)
    return alert


@app.get("/assets/{key}")
def get_asset(key: str):
    asset = data.get_asset(key)
    if not asset:
        raise HTTPException(404, "no está en la CMDB (¿equipo externo o no gestionado?)")
    return asset


@app.get("/users/{key}")
def get_user(key: str):
    user = data.get_user(key)
    if not user:
        raise HTTPException(404)
    return user


@app.get("/logs/{source}")
def search_logs(source: str, q: str = "", desde: str = "", hasta: str = "", limit: int = Query(200, le=2000)):
    if source not in LOG_SOURCES:
        raise HTTPException(404, f"fuente desconocida: {source}")
    return _parse_or_400(data.search_logs, source, q=q, start=desde or None, end=hasta or None, limit=limit)


@app.get("/intel/{indicator}")
def intel(indicator: str):
    return data.get_intel(indicator)


@app.get("/sandbox/{sha256}")
def sandbox(sha256: str):
    report = data.get_sandbox(sha256)
    if not report:
        raise HTTPException(404, "sin informe: el fichero no se ha enviado a la sandbox")
    return report


@app.get("/changes")
def changes(q: str = "", host: str = "", at: str = ""):
    return _parse_or_400(data.find_changes, q=q, host=host or None, at=at or None)


# Extra read endpoints that the mock API doesn't have.
@app.get("/entities/{entity}/timeline")
def entity_timeline(
    entity: str,
    entity_type: str = "",
    desde: str = "",
    hasta: str = "",
    sources: str = Query("", description="Comma-separated log sources"),
    limit: int = Query(200, le=2000),
):
    if not entity_type and data.detect_entity_type(entity) == "unknown":
        # Answering with an empty timeline would make an unknown indicator look clean.
        raise HTTPException(400, f"no se reconoce el tipo de {entity!r}: indica entity_type")
    source_list = [s.strip() for s in sources.split(",") if s.strip()]
    return _parse_or_400(
        data.timeline, entity, entity_type=entity_type or None, start=desde or None, end=hasta or None,
        sources=source_list or None, limit=limit,
    )


@app.get("/events/{event_id}")
def get_event(event_id: str):
    event = data.get_event(event_id)
    if not event:
        raise HTTPException(404)
    return event


@app.get("/mentions")
def mentions(text: str, desde: str = "", hasta: str = "", limit: int = Query(200, le=2000)):
    return _parse_or_400(data.mentions, text, start=desde or None, end=hasta or None, limit=limit)


@app.get("/resolve/ip/{ip}")
def resolve_ip(ip: str, at: str = ""):
    return _parse_or_400(data.resolve_ip, ip, at=at or None)


@app.get("/users/{user}/hosts")
def hosts_for_user(user: str, desde: str = "", hasta: str = ""):
    return _parse_or_400(data.hosts_for_user, user, start=desde or None, end=hasta or None)


@app.get("/assets/{host}/users")
def users_for_host(host: str, desde: str = "", hasta: str = ""):
    return _parse_or_400(data.users_for_host, host, start=desde or None, end=hasta or None)


class Approval(BaseModel):
    action: str
    target: str
    approver: str
    reason: str = ""
    ticket_id: str = Field(min_length=1)


@app.post("/approvals")
def approve(approval: Approval):
    token = "APR-" + uuid.uuid4().hex[:10]
    now = time.monotonic()
    with _approvals_lock:
        for old in [t for t, a in APPROVALS.items() if a["expires_at"] <= now]:
            del APPROVALS[old]
        APPROVALS[token] = {**approval.model_dump(), "expires_at": now + TOKEN_TTL_SECONDS}
    return {"approval_token": token, **approval.model_dump()}


def _use_token(token: str, action: str, target: str, ticket_id: str) -> bool:
    """Spend a token if it is live and was issued for exactly this action, target and ticket."""
    with _approvals_lock:
        approval = APPROVALS.get(token)
        if not approval or approval["expires_at"] <= time.monotonic():
            return False
        if (approval["action"], approval["target"], approval["ticket_id"]) != (action, target, ticket_id):
            return False
        del APPROVALS[token]
        return True


class Action(BaseModel):
    target: str
    justification: str
    approval_token: str = ""
    ticket_id: str = ""


@app.post("/containment/{action}")
def contain(action: str, request: Action):
    if action not in VALID:
        raise HTTPException(400, f"acción no soportada: {action}")
    try:
        asset = data.action_target_asset(request.target)
        user = data.get_user(request.target) if action == "disable_user" else None
        check = policy.action_policy(action, request.target, asset=asset, user=user)
    except Exception as error:  # never guess that a target is safe
        raise HTTPException(503, "no se pudo comprobar el objetivo, así que la acción se bloquea") from error
    if not check["allowed"]:
        raise HTTPException(403, "política: " + " ".join(check["notes"]))
    if check["human_confirmation_required"] and not _use_token(request.approval_token, action, request.target, request.ticket_id):
        raise HTTPException(403, "falta aprobación humana válida para esta acción, objetivo y ticket")
    timestamp = dt.datetime.now(dt.timezone.utc).replace(tzinfo=None).isoformat() + "Z"
    record = {"timestamp": timestamp, "action": action, **request.model_dump(exclude={"approval_token"}), "result": "ok (simulado)"}
    with _log_lock:
        LOGFILE.parent.mkdir(parents=True, exist_ok=True)
        with open(LOGFILE, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    return record


@app.get("/containment/log")
def containment_log():
    if not LOGFILE.exists():
        return []
    with open(LOGFILE, encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]
