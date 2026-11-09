"""Attacker-written text in an alert: the single list of fields, and how to find them.

Email bodies and subjects, prompts sent to AI tools, service descriptions, command lines, user agents,
package scripts… are written by whoever triggered the alert, so they are DATA, never instructions.
The collectors copy them to the EvidencePack's `untrusted` list (`untrusted_fields`). The prompt
builder (`triage/prompts/builder.py`) fences exactly these fields in place, with a per-pack nonce and
`<`/`>` escaped, and the system prompt tells the model that fenced text is never an instruction.

This is the ONLY list of attacker-writable fields: add new ones here, not in the prompt builder.
"""
from __future__ import annotations

from typing import Any

# Evidence keys whose text may be written by the attacker (or by any third party).
UNTRUSTED_EVIDENCE_KEYS = (
    # mail
    "subject", "body_excerpt", "email_body_excerpt", "attachment_name", "file_name",
    # AI assistant
    "prompt_excerpt", "tool_result",
    # endpoint / services / packages
    "command_line", "decoded_preview", "service_description", "description_text", "process_tree",
    "parent_chain", "postinstall",
    # web / network
    "user_agent", "original_user_agent", "new_user_agent", "url", "uri", "query", "downloaded_from",
    # detection text that can echo attacker input
    "rule_name",
    "texto",  # a live alert whose evidence came as plain text (collectors._normal_shape)
)


def untrusted_fields(alert: dict[str, Any]) -> list[dict[str, str]]:
    """[{"field": "evidence.body_excerpt", "text": ...}] for every attacker-writable text in the alert."""
    out: list[dict[str, str]] = []
    ev = alert.get("evidence")
    if isinstance(ev, str) and ev.strip():
        out.append({"field": "evidence", "text": ev})
    elif isinstance(ev, dict):
        for key in UNTRUSTED_EVIDENCE_KEYS:
            if isinstance(ev.get(key), str) and ev[key].strip():
                out.append({"field": f"evidence.{key}", "text": ev[key]})
    ents = alert.get("entities")
    procs = ents.get("processes") if isinstance(ents, dict) else None
    for i, proc in enumerate(procs if isinstance(procs, list) else []):
        if isinstance(proc, dict) and proc.get("command_line"):
            out.append({"field": f"entities.processes[{i}].command_line", "text": str(proc["command_line"])})
    return out
