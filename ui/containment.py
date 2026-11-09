"""The only code allowed to approve or execute containment, always after a person's click in the console.

It lives in `ui/` on purpose: the AI side (`triage/`) must never import it, because `/approvals` issues a
token to any caller. tests/test_actions.py enforces that.

Containment here only ever reaches the simulated SOC API.
"""
from __future__ import annotations

import os
from typing import Any

import requests

from triage import data, policy
from triage.store import Store


class ContainmentRefused(ValueError):
    """The action wasn't sent to the API: the policy forbids it, or something is missing."""


class ContainmentFailed(RuntimeError):
    """The API couldn't be reached or refused the action."""


def api_url() -> str:
    return os.environ.get("SOC_API_URL", "http://127.0.0.1:8000").rstrip("/")


def _post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    try:
        response = requests.post(api_url() + path, json=payload, timeout=20)
    except requests.RequestException as error:
        raise ContainmentFailed(
            f"No se puede conectar con la API del SOC en {api_url()}. Arráncala con: uvicorn api.soc_api:app --port 8000"
        ) from error
    if response.status_code != 200:
        try:
            detail = response.json().get("detail", response.text)
        except ValueError:
            detail = response.text
        raise ContainmentFailed(f"La API rechazó la acción ({response.status_code}): {detail}")
    return response.json()


def containment_log() -> list[dict[str, Any]]:
    try:
        response = requests.get(api_url() + "/containment/log", timeout=20)
        response.raise_for_status()
    except requests.RequestException as error:
        raise ContainmentFailed(f"No se puede leer el registro de {api_url()}.") from error
    return response.json()


def is_containment(action: str) -> bool:
    return action in policy.ACTIONS


def check_action(action: str, target: str) -> dict[str, Any]:
    """Ask the policy who may run this action on this target.

    If the asset or user can't be looked up, the action is blocked: never guess that a target is safe.
    """
    try:
        asset = data.action_target_asset(target)
        user = data.get_user(target) if action == "disable_user" else None
    except Exception as error:
        return {"action": action, "target": target, "allowed": False, "requires_approval": True, "approvers": [],
                "notes": [f"No se pudo comprobar el objetivo, así que se bloquea por seguridad ({error.__class__.__name__})."]}
    return policy.action_policy(action, target, asset=asset, user=user)


def latest_decision(ticket: dict[str, Any], action: str, target: str) -> dict[str, Any] | None:
    decisions = [d for d in ticket.get("action_decisions", []) if d["action"] == action and d["target"] == target]
    return decisions[-1] if decisions else None


def approve_and_execute(store: Store, ticket_id: str, action: str, target: str, approver: str, justification: str) -> dict[str, Any]:
    """Run one containment action a person just approved, and log every step on the ticket."""
    if not approver.strip():
        raise ContainmentRefused("Escribe tu nombre: cada acción necesita una persona responsable.")
    ticket = store.get_ticket(ticket_id)
    if ticket is None:
        raise ContainmentRefused(f"No existe el ticket {ticket_id}.")
    if not is_containment(action):
        raise ContainmentRefused(f"«{action}» no es una acción de contención.")
    previous = latest_decision(ticket, action, target)
    if previous and previous["decision"] == "executed":
        raise ContainmentRefused("Esta acción ya se ejecutó.")
    check = check_action(action, target)
    if not check["allowed"]:
        raise ContainmentRefused(" ".join(check["notes"]) or "La política no permite esta acción.")

    note = justification.strip() or "Aprobada en la consola"
    store.record_action(ticket_id, action, target, "approved", approver, reason=note)
    try:
        # The API wants a token for every action (D-4). It is used once here and never saved.
        token = _post("/approvals", {"action": action, "target": target, "approver": approver.strip(), "reason": note, "ticket_id": ticket_id})["approval_token"]
        result = _post(f"/containment/{action}", {"target": target, "justification": note, "approval_token": token, "ticket_id": ticket_id})
    except ContainmentFailed as error:
        store.record_action(ticket_id, action, target, "failed", approver, reason=str(error))
        raise
    result.pop("approval_token", None)
    store.record_action(ticket_id, action, target, "executed", approver, reason=note, result=result)
    return result


def reject(store: Store, ticket_id: str, action: str, target: str, approver: str, reason: str) -> None:
    """Record that a person rejected an action. Nothing reaches the API."""
    store.record_action(ticket_id, action, target, "rejected", approver, reason=reason)


def build_override(ticket: dict[str, Any], verdict: str, severity: str) -> dict[str, str]:
    """Only what actually differs from the AI's conclusion."""
    override = {}
    if verdict != ticket.get("verdict"):
        override["verdict"] = verdict
    if severity != ticket.get("severity"):
        override["severity"] = severity
    return override
