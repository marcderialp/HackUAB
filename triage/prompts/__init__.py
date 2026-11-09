"""C2 triage prompts: base system prompt, one specialist per runbook, and the EvidencePack builder."""
from triage.prompts.builder import (
    PROMPT_VERSION,
    RUNBOOKS,
    TriagePrompt,
    build_prompt,
    check_citations,
    run_prompt,
)

__all__ = ["PROMPT_VERSION", "RUNBOOKS", "TriagePrompt", "build_prompt", "check_citations", "run_prompt"]
