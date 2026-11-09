"""Offline tests for triage/llm.py against the OpenAI-compatible chat completions protocol.

No network: an openai client over httpx2.MockTransport fakes the UAB DCC gateway. Response
and error bodies mirror what the real gateway returned when probed on 2026-11-07.
"""

from __future__ import annotations

import json
import threading
from types import SimpleNamespace

import httpx2
import openai
import pytest

from triage import llm
from triage.schemas import LLMVerdict

BASE = "https://dcc-llm-gw.uab.cat/uabthehack/v1"
TEST_KEY = "sk-test-not-a-real-key-0123456789abcdef"

VALID = {
    "title": "Inventario SCCM legítimo",
    "verdict": "benign_true_positive",
    "confidence": 0.9,
    "summary": "PowerShell codificado lanzado por CcmExec.",
    "evidence": [{"event_id": "EDR-7000123", "source": "edr", "finding": "Padre CcmExec.exe"}],
    "adjustments": [{"delta": -1, "reason_type": "blocked_no_effect", "reason": "x"}],
    "mitre": ["T1059.001"],
    "recommended_actions": [{"action": "close", "target": "ticket", "justification": "Cambio aprobado"}],
    "escalation_suggestion": {"escalate": False, "to": "", "reason": ""},
    "open_questions": [],
    "injection_detected": [],
}


def _completion(content=None, finish="stop", model="ornith", refusal=None, prompt=900, completion=700, reasoning=400,
                cached=0):
    """Shape of the gateway's chat.completion body (as observed when probing it)."""
    return {
        "id": "chatcmpl-test", "object": "chat.completion", "created": 0, "model": model,
        "choices": [{"index": 0, "finish_reason": finish, "message": {
            "role": "assistant", "content": json.dumps(VALID) if content is None else content,
            "refusal": refusal, "reasoning": "razonamiento interno"}}],
        "usage": {"prompt_tokens": prompt, "completion_tokens": completion, "total_tokens": prompt + completion,
                  "completion_tokens_details": {"reasoning_tokens": reasoning},
                  "prompt_tokens_details": {"cached_tokens": cached}},
    }


def _error(status, message, kind):
    return httpx2.Response(status, json={"message": message, "type": kind})


class FakeGateway:
    """httpx2.MockTransport handler: records requests, replays scripted replies."""

    def __init__(self, *replies):
        self.replies = list(replies)
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        if isinstance(reply, httpx2.Response):
            return reply
        return httpx2.Response(200, json=reply)

    def client(self):
        return openai.OpenAI(base_url=BASE, api_key=TEST_KEY, max_retries=0,
                             http_client=httpx2.Client(transport=httpx2.MockTransport(self)))

    def sent(self, i=0):
        return json.loads(self.requests[i].content)


class NetworkForbidden:
    """Any use means a test tried to reach a server."""

    def __getattr__(self, name):
        raise AssertionError(f"client used: .{name}")


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    monkeypatch.setattr(llm, "RESPONSE_CACHE_DIR", tmp_path / "llm_cache")
    monkeypatch.setattr(llm, "CALL_LOG", tmp_path / "llm_calls.jsonl")
    for var in ("LLM_OFFLINE", "LLM_DISABLE_CACHE", "LLM_MAX_OUTPUT_TOKENS", "LLM_TIMEOUT_S", "LLM_THINKING"):
        monkeypatch.delenv(var, raising=False)
    # Importing triage.llm loads the real .env: pin a known test configuration instead.
    monkeypatch.setenv("LLM_PROVIDER", "openai_compatible")
    monkeypatch.setenv("LLM_BASE_URL", BASE)
    monkeypatch.setenv("LLM_MODEL", "ornith")
    monkeypatch.setenv("LLM_API_KEY", TEST_KEY)
    llm.set_client(NetworkForbidden())  # no test may reach the real gateway by accident
    yield SimpleNamespace(path=tmp_path)
    llm.set_client(None)


def _call(user="alert-1", **kw):
    return llm.call_structured(system=["base prompt", "runbook RB-02"], user=user,
                               output_model=LLMVerdict, prompt_version="test-v1", **kw)


def _use(fake):
    llm.set_client(fake.client())
    return fake


def _log_text(isolated):
    return (isolated.path / "llm_calls.jsonl").read_text(encoding="utf-8")


def _log(isolated):
    return [json.loads(l) for l in _log_text(isolated).splitlines()]


# --- request construction and response parsing ----------------------------------------


def test_request_shape_and_parsing():
    fake = _use(FakeGateway(_completion(cached=100)))
    res = _call()
    assert res.ok and res.parsed.verdict == "benign_true_positive"
    req = fake.requests[0]
    assert str(req.url) == f"{BASE}/chat/completions" and req.method == "POST"
    assert req.headers["authorization"] == f"Bearer {TEST_KEY}"
    sent = fake.sent()
    assert sent["model"] == "ornith" and sent["temperature"] == 0.0 and sent["seed"] == 42
    assert sent["max_tokens"] == 4096
    assert sent["chat_template_kwargs"] == {"enable_thinking": False}  # thinking off by default (extra_body)
    assert sent["messages"] == [{"role": "system", "content": "base prompt\n\nrunbook RB-02"},
                                {"role": "user", "content": "alert-1"}]
    rf = sent["response_format"]
    assert rf["type"] == "json_schema" and rf["json_schema"]["strict"] is True
    assert rf["json_schema"]["name"] == "LLMVerdict" and rf["json_schema"]["schema"] == LLMVerdict.model_json_schema()
    assert "reasoning_effort" not in sent  # accepted by the gateway but without verified effect
    m = res.meta
    assert (m.tokens_in, m.cache_read_tokens, m.tokens_out, m.reasoning_tokens) == (800, 100, 700, 400)
    assert m.served_model == "ornith" and m.stop_reason == "stop" and m.request_id == "chatcmpl-test"
    assert m.cost_usd == 0.0 and m.fallback_used is False and m.thinking_level == "off"


def test_thinking_on_sends_no_switch(monkeypatch, isolated):
    monkeypatch.setenv("LLM_THINKING", "on")
    fake = _use(FakeGateway(_completion()))
    res = _call()
    assert res.ok and "chat_template_kwargs" not in fake.sent() and res.meta.thinking_level == "on"
    assert _log(isolated)[-1]["thinking_level"] == "on"


@pytest.mark.parametrize("value", ["false", "yes", "auto"])
def test_unknown_thinking_value_is_a_config_error(monkeypatch, value):
    monkeypatch.setenv("LLM_THINKING", value)
    res = _call()
    assert res.status == "error" and res.meta.error_kind == "config_error"


def test_thinking_flag_changes_the_cache_key(monkeypatch):
    fake = _use(FakeGateway(_completion(), _completion()))
    off = _call()
    monkeypatch.setenv("LLM_THINKING", "on")
    on = _call()
    assert off.meta.cache_key != on.meta.cache_key and len(fake.requests) == 2
    monkeypatch.setenv("LLM_THINKING", "off")
    again = _call()
    assert again.meta.disk_cache_hit and again.meta.cache_key == off.meta.cache_key


@pytest.mark.parametrize("effort", ["low", "medium", "high", "xhigh", "max"])
def test_every_accepted_effort_still_works(effort):
    fake = _use(FakeGateway(_completion()))
    res = _call(effort=effort)
    assert res.ok and res.meta.effort == effort and "reasoning_effort" not in fake.sent()


def test_unknown_effort_is_a_programming_error():
    with pytest.raises(ValueError):
        _call(effort="minimal")


@pytest.mark.parametrize("max_tokens,env,expected", [(16000, None, 4096), (3000, None, 3000), (16000, "12000", 12000)])
def test_output_budget(monkeypatch, max_tokens, env, expected):
    if env:
        monkeypatch.setenv("LLM_MAX_OUTPUT_TOKENS", env)
    fake = _use(FakeGateway(_completion()))
    _call(max_tokens=max_tokens)
    assert fake.sent()["max_tokens"] == expected


def test_model_argument_overrides_env():
    fake = _use(FakeGateway(_completion(model="other-model")))
    res = _call(model="other-model")
    assert fake.sent()["model"] == "other-model" and res.meta.served_model == "other-model"


# --- configuration and endpoint allowlist ---------------------------------------------------


@pytest.mark.parametrize("url", [
    "http://dcc-llm-gw.uab.cat/uabthehack/v1",  # not https
    "https://api.openai.com/v1",
    "https://dcc-llm-gw.uab.cat.evil.example/v1",
    "http://127.0.0.1:11434/v1",
])
def test_endpoint_outside_allowlist_is_refused(monkeypatch, url, isolated):
    monkeypatch.setenv("LLM_BASE_URL", url)
    llm.set_client(None)
    res = _call()
    assert res.status == "error" and res.meta.error_kind == "endpoint_not_allowed"
    assert not (isolated.path / "llm_cache").exists()


def test_wrong_provider_is_refused(monkeypatch):
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    llm.set_client(None)
    res = _call()
    assert res.meta.error_kind == "config_error"


def test_missing_api_key(monkeypatch):
    monkeypatch.delenv("LLM_API_KEY")
    llm.set_client(None)
    res = _call()
    assert res.status == "error" and res.meta.error_kind == "missing_api_key"


def test_client_built_from_env_uses_base_url_and_key():
    llm.set_client(None)
    client = llm.get_client()
    assert str(client.base_url).rstrip("/") == BASE and client.api_key == TEST_KEY
    assert client.max_retries == llm.SDK_MAX_RETRIES


# --- validation and retries ------------------------------------------------------------------


def test_invalid_output_retried_once_then_reported():
    bad = dict(VALID, confidence=1.7)
    fake = _use(FakeGateway(_completion(json.dumps(bad)), _completion("no es json")))
    res = _call()
    assert res.status == "invalid" and res.parsed is None and res.meta.attempts == 2
    assert res.meta.error_kind == "schema_validation" and len(fake.requests) == 2


def test_invalid_then_valid_recovers():
    _use(FakeGateway(_completion("{}"), _completion()))
    res = _call()
    assert res.ok and res.meta.attempts == 2


def test_missing_required_field_is_invalid():
    partial = json.dumps({k: v for k, v in VALID.items() if k != "verdict"})
    _use(FakeGateway(_completion(partial), _completion(partial)))
    assert _call().status == "invalid"


def test_truncation_is_not_retried():
    fake = _use(FakeGateway(_completion("", finish="length"), _completion()))  # a 2nd reply would succeed
    res = _call()
    assert res.status == "invalid" and res.meta.error_kind == "truncated" and "reasoning" in res.meta.error
    assert res.meta.attempts == 1 and len(fake.requests) == 1


LOOP = '{"title": "x", "verdict": "true_positive",' + " " * 500  # whitespace loop mid-object


def test_whitespace_loop_is_retried_once_at_a_different_temperature():
    fake = _use(FakeGateway(_completion(LOOP, finish="length"), _completion()))
    res = _call()
    assert res.ok and res.meta.attempts == 2 and res.meta.retry_reason == "whitespace_loop"
    first, second = fake.sent(0), fake.sent(1)
    assert first["temperature"] == 0.0 and second["temperature"] == llm.WHITESPACE_RETRY_TEMPERATURE
    assert {k: v for k, v in first.items() if k != "temperature"} == {k: v for k, v in second.items() if k != "temperature"}


def test_whitespace_loop_retry_stops_after_one():
    fake = _use(FakeGateway(_completion(LOOP, finish="length"), _completion(LOOP, finish="length"), _completion()))
    res = _call()
    assert res.status == "invalid" and res.meta.error_kind == "truncated" and len(fake.requests) == 2


def test_whitespace_retry_keeps_the_original_cache_key():
    fake = _use(FakeGateway(_completion(LOOP, finish="length"), _completion()))
    retried = _call()
    plain = _call()  # identical request: served from the cache entry written after the retry
    assert plain.meta.disk_cache_hit and plain.meta.cache_key == retried.meta.cache_key and len(fake.requests) == 2


def test_short_trailing_whitespace_is_plain_truncation():
    fake = _use(FakeGateway(_completion('{"title": "x"' + " " * 50, finish="length"), _completion()))
    res = _call()
    assert res.meta.error_kind == "truncated" and res.meta.attempts == 1 and len(fake.requests) == 1


def test_schema_validation_still_gets_a_second_attempt():
    fake = _use(FakeGateway(_completion("{}"), _completion()))
    res = _call()
    assert res.ok and res.meta.attempts == 2 and len(fake.requests) == 2


@pytest.mark.parametrize("first", ["{}", ""])
def test_validation_retry_changes_the_request(first):
    """At temperature 0 an identical retry repeats the same output, so the second attempt must differ."""
    fake = _use(FakeGateway(_completion(first), _completion()))
    res = _call()
    assert res.ok and res.meta.retry_reason in ("schema_validation", "empty_content")
    first_req, second_req = (json.loads(r.content) for r in fake.requests)
    assert first_req["temperature"] == 0 and second_req["temperature"] == llm.RETRY_TEMPERATURE
    assert {k: v for k, v in first_req.items() if k != "temperature"} == \
           {k: v for k, v in second_req.items() if k != "temperature"}


def test_empty_content_is_invalid():
    _use(FakeGateway(_completion(""), _completion("")))
    assert _call().meta.error_kind == "empty_content"


def test_old_reason_names_are_rejected():
    old = json.dumps(dict(VALID, adjustments=[{"delta": 1, "reason_type": "confirmed_execution_or_access", "reason": "x"}]))
    _use(FakeGateway(_completion(old), _completion(old)))
    assert _call().status == "invalid"


def test_refusal_field_maps_to_refusal_status(isolated):
    _use(FakeGateway(_completion(content=None, refusal="I can't help with that")))
    res = _call()
    assert res.status == "refusal" and res.parsed is None and res.meta.refusal_category == "refusal"
    assert not (isolated.path / "llm_cache").exists()
    assert llm.needs_more_info_verdict(res).verdict == "needs_more_info"


def test_content_filter_maps_to_refusal():
    _use(FakeGateway(_completion("", finish="content_filter")))
    assert _call().meta.refusal_category == "content_filter"


# --- API and transport errors (bodies as returned by the real gateway) ------------------------


@pytest.mark.parametrize("response,kind", [
    (_error(401, "Clau no vàlida o desactivada.", "invalid_api_key"), "auth_failed"),
    (_error(403, "Forbidden", "permission_denied"), "permission_denied"),
    (_error(404, "Model desconegut: x. Models disponibles: ornith", "model_not_found"), "model_not_available"),
    (_error(429, "Rate limit exceeded", "rate_limit"), "rate_limited"),
    (_error(400, "This model's maximum context length is 32768 tokens", "invalid_request_error"), "context_overflow"),
    (_error(400, "Invalid parameter: response_format", "invalid_request_error"), "bad_request"),
    (_error(500, "Internal error", "server_error"), "server_error"),
    (_error(503, "Service unavailable", "server_error"), "server_error"),
])
def test_api_errors_are_classified(response, kind, isolated):
    fake = _use(FakeGateway(response))
    res = _call()
    assert res.status == "error" and res.meta.error_kind == kind and len(fake.requests) == 1
    assert res.parsed is None and not (isolated.path / "llm_cache").exists()


def test_timeout():
    _use(FakeGateway(httpx2.ReadTimeout("timed out")))
    assert _call().meta.error_kind == "timeout"


def test_connection_refused():
    _use(FakeGateway(httpx2.ConnectError("connection refused")))
    res = _call()
    assert res.status == "error" and res.meta.error_kind == "server_unavailable"


@pytest.mark.parametrize("response", [
    httpx2.Response(200, text="<html>not json</html>"),
    httpx2.Response(200, json={"id": "x", "object": "chat.completion", "model": "ornith", "choices": []}),
    httpx2.Response(200, json={"unexpected": True}),
])
def test_malformed_response_body(response):
    fake = _use(FakeGateway(response))
    res = _call()
    assert res.status == "error" and res.meta.error_kind == "malformed_response" and len(fake.requests) == 1


def test_sdk_retries_rate_limits_then_reports(monkeypatch):
    fake = FakeGateway(*[_error(429, "Rate limit exceeded", "rate_limit")] * 3)
    llm.set_client(openai.OpenAI(base_url=BASE, api_key=TEST_KEY, max_retries=2,
                                 http_client=httpx2.Client(transport=httpx2.MockTransport(fake))))
    monkeypatch.setattr(openai._base_client.SyncAPIClient, "_calculate_retry_timeout", lambda *a, **k: 0)
    res = _call()
    assert res.meta.error_kind == "rate_limited" and len(fake.requests) == 3  # 1 try + 2 SDK retries


@pytest.mark.parametrize("kind", ["rate_limited", "server_unavailable", "auth_failed", "context_overflow"])
def test_errors_map_to_needs_more_info(kind):
    meta = llm.CallMeta(tag="", model="ornith", served_model=None, effort="low", prompt_version="v",
                        cache_key="", disk_cache_hit=False, status="error", error_kind=kind, error="x")
    v = llm.needs_more_info_verdict(llm.LLMResult("error", None, None, meta))
    assert v.verdict == "needs_more_info" and v.confidence == 0 and v.escalation_suggestion.escalate


# --- secrets ---------------------------------------------------------------------------------


def test_api_key_never_appears_in_log_or_errors(isolated):
    echo = _error(401, f"bad key {TEST_KEY}", "invalid_api_key")  # a server echoing the key back
    _use(FakeGateway(echo))
    res = _call(user="ALR-PROMPT-TEXT")
    assert TEST_KEY not in (res.meta.error or "") and "<redacted>" in res.meta.error
    text = _log_text(isolated)
    assert TEST_KEY not in text and "ALR-PROMPT-TEXT" not in text and "base prompt" not in text


# --- cache, offline, dedup, logging ----------------------------------------------------------


def test_disk_cache_hit_avoids_second_call(isolated):
    fake = _use(FakeGateway(_completion()))
    first, second = _call(), _call()
    assert len(fake.requests) == 1
    assert not first.meta.disk_cache_hit and second.meta.disk_cache_hit
    assert second.meta.served_model == "ornith"
    assert [r["disk_cache_hit"] for r in _log(isolated)] == [False, True]


def test_cache_is_isolated_between_models():
    fake = _use(FakeGateway(_completion(model="ornith"), _completion(model="other-model")))
    a, b = _call(), _call(model="other-model")
    assert len(fake.requests) == 2 and a.meta.cache_key != b.meta.cache_key
    assert _call().meta.served_model == "ornith" and _call(model="other-model").meta.served_model == "other-model"
    assert len(fake.requests) == 2


def test_cache_key_changes_with_prompt_version_and_budget(monkeypatch):
    fake = _use(FakeGateway(*[_completion() for _ in range(3)]))
    _call()
    llm.call_structured(system=["base prompt", "runbook RB-02"], user="alert-1",
                        output_model=LLMVerdict, prompt_version="test-v2")
    monkeypatch.setenv("LLM_MAX_OUTPUT_TOKENS", "2048")  # differs from the 4096 default
    _call()
    assert len(fake.requests) == 3


def test_offline_mode_never_builds_a_client(monkeypatch):
    monkeypatch.setenv("LLM_OFFLINE", "1")
    llm.set_client(None)
    monkeypatch.setattr(llm.openai, "OpenAI", lambda *a, **k: (_ for _ in ()).throw(AssertionError("client built")))
    res = _call()
    assert res.status == "error" and res.meta.error_kind == "offline_cache_miss"


def test_offline_mode_replays_cached_answer(monkeypatch):
    _use(FakeGateway(_completion()))
    assert _call().ok
    monkeypatch.setenv("LLM_OFFLINE", "1")
    llm.set_client(NetworkForbidden())
    res = _call()
    assert res.ok and res.meta.disk_cache_hit


def test_concurrent_identical_requests_make_one_call():
    fake = _use(FakeGateway(_completion()))
    results = []
    threads = [threading.Thread(target=lambda: results.append(_call())) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(fake.requests) == 1 and all(r.ok for r in results)


def test_log_fields(isolated):
    _use(FakeGateway(_completion()))
    _call()
    entry = _log(isolated)[-1]
    for k in ("model", "served_model", "effort", "error_kind", "tokens_in", "tokens_out", "reasoning_tokens",
              "cache_read_tokens", "cost_usd", "fallback_used", "latency_s", "stop_reason", "request_id"):
        assert k in entry


def test_missing_usage_does_not_break_the_call():
    body = _completion()
    body.pop("usage")
    _use(FakeGateway(body))
    res = _call()
    assert res.ok and (res.meta.tokens_in, res.meta.tokens_out) == (0, 0)


# --- schema ----------------------------------------------------------------------------------


def test_reason_names_match_the_agreed_contract():
    schema = LLMVerdict.model_json_schema()
    reasons = schema["$defs"]["Adjustment"]["properties"]["reason_type"]["enum"]
    assert reasons == ["confirmed_execution", "vip_privileged", "personal_data_payments", "blocked_no_effect"]
    assert schema["$defs"]["Adjustment"]["properties"]["delta"]["enum"] == [-1, 1]


def test_schema_is_valid_for_strict_mode():
    """Strict json_schema needs every object closed and every property required."""

    def walk(node):
        if isinstance(node, dict):
            if node.get("type") == "object":
                assert node.get("additionalProperties") is False
                assert set(node.get("required", [])) == set(node.get("properties", {}))
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(LLMVerdict.model_json_schema())
