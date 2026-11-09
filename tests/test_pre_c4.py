"""Pre-C4 hardening of B2/B3: compact pack for the LLM, shared-exit fact (RB-03), activity after an
employee's last day, young-domain check."""
import copy
import json

import pytest

from triage import data
from triage.collectors import collect, for_llm
from triage.collectors.network import _young_domain
from triage.context import context_for
from triage.prompts.builder import build_prompt, evidence_ids

SCCM = "ALR-20261012-700075"  # s10 SCCM inventory: CHG-2026-2103 applies, the other active changes don't
TRAVEL = "ALR-20261013-700041"  # s05 impossible travel: the Barcelona office exit (shared) and a carrier IP
UPLOAD = "ALR-20261015-700124"  # s12: didac.ubach, whose last working day is 23/10, uploads an ERP export


def after_last_day():
    """The same upload re-dated to four days after his last working day (the dataset's week ends on 18/10).
    No related events, so the alert's own time is the activity's time."""
    alert = copy.deepcopy(data.get_alert(UPLOAD))
    alert.update(alert_id="ALR-TEST-DEPARTED", created_at="2026-10-27T08:05:00.000Z", related_events=[])
    return alert


# ---------------------------------------------------------------- for_llm

def test_for_llm_keeps_every_citable_event_and_is_smaller():
    pack = collect(data.get_alert(SCCM))
    full = {k: v for k, v in pack.items() if k != "trace"}
    view = for_llm(pack)
    assert evidence_ids(view) == evidence_ids(full)
    assert len(json.dumps(view, ensure_ascii=False)) < len(json.dumps(full, ensure_ascii=False))
    assert "trace" not in view and "trace" in pack  # input untouched


def test_for_llm_keeps_applying_changes_whole_and_summarises_the_rest():
    view = for_llm(collect(data.get_alert(SCCM)))
    changes = view["context"]["changes"]
    applying = [c for c in changes if c["applies"] is True]
    assert applying and all(c.get("checks") for c in applying)
    for c in changes:
        if c["applies"] is False:
            assert "checks" not in c and c["no_aplica_por"]
    assert "alert_id" not in view["context"]  # duplicated top-level fields are dropped


def test_builder_uses_for_llm_and_still_knows_the_authorizations():
    pack = collect(data.get_alert(SCCM))
    p = build_prompt(pack)
    assert p.authorized_changes  # computed from the full pack
    assert '"no_aplica_por"' in p.user  # the compact view is what the model sees


# ---------------------------------------------------------------- RB-03 shared exit

def test_many_accounts_without_failures_is_a_shared_exit_not_spraying():
    findings = collect(data.get_alert(TRAVEL))["findings"]
    origin = [f for f in findings if "sin ningún fallo" in f["fact"]]
    assert origin and not origin[0]["notable"]
    shared = [f for f in findings if f["check"] == "RB-03.1 salida compartida"]
    assert shared and "IP de salida compartida" in shared[0]["fact"] and shared[0]["event_ids"]


# ---------------------------------------------------------------- HR

def test_activity_after_the_last_day_is_flagged():
    flags = {f["flag"]: f for f in context_for(after_last_day())["flags"]}
    assert flags["hr_departed"]["applies"] is True and "después de su último día" in flags["hr_departed"]["detail"]
    # The real upload (15/10) comes before his last day: he is leaving, not gone.
    assert "hr_departed" not in {f["flag"] for f in context_for(data.get_alert(UPLOAD))["flags"]}


def test_hr_departed_is_highlighted_in_the_pack():
    findings = collect(after_last_day())["findings"]
    # The HR notice itself also says "último día", so look for the departed fact's own wording.
    assert any(f["notable"] and "después de su último día" in f["fact"] for f in findings)


# ---------------------------------------------------------------- young domain

@pytest.mark.parametrize("age,young", [(0, True), (5, True), ("12", True), (29.5, True), (30, False),
                                       (400, False), (None, False), ("n/d", False)])
def test_young_domain_counts_zero_days(age, young):
    assert _young_domain(age) is young
