"""Tests for the optional AI narrative layer (hardax/ai.py). These never hit
the network; they cover the privacy guarantees (redaction, payload whitelist,
egress consent) and failure handling."""
import json

from hardax import ai


def test_redact_scrubs_ip_mac_and_long_hex():
    text = "host 192.168.1.5 port 5555 mac 00:11:22:33:44:55 tok deadbeefdeadbeef"
    out = ai._redact(text)
    assert "192.168.1.5" not in out and "[ip]" in out
    assert "00:11:22:33:44:55" not in out and "[mac]" in out
    assert "deadbeefdeadbeef" not in out and "[hex]" in out


def test_build_payload_never_includes_raw_check_output():
    analysis = {
        "risk_score": 55, "grade": "D", "profile": "pos", "totals": {"critical": 2},
        "attack_chains": [{"name": "chain", "severity": "critical",
                           "steps": [{"label": "L", "category": "C", "status": "CRITICAL"}]}],
        "priorities": [{"label": "P", "category": "NETWORK", "status": "CRITICAL",
                        "remediation": "fix it", "rank": 1, "in_attack_chain": True}],
        "verify_clusters": [],
    }
    payload = ai._build_payload(analysis)
    # The raw per-check output lives under a "result" key in engine rows and must
    # never reach the payload. The whitelist must also drop internal fields.
    dumped = json.dumps(payload)
    assert "result" not in dumped
    assert payload["risk_score"] == 55 and payload["grade"] == "D"
    # attack-chain steps are reduced to bare labels
    assert payload["attack_chains"][0]["steps"] == ["L"]


def test_resolve_key_prefers_explicit_then_env(monkeypatch):
    monkeypatch.setenv("ANTHROPIC_API_KEY", "env-secret")
    assert ai.resolve_key("anthropic", "explicit") == "explicit"
    assert ai.resolve_key("anthropic", None) == "env-secret"
    # ollama needs no key
    assert ai.resolve_key("ollama", None) is None


def test_is_cloud():
    assert ai.is_cloud("anthropic") and ai.is_cloud("openai")
    assert not ai.is_cloud("ollama")


def test_egress_consent_local_provider_always_ok():
    assert ai.egress_consent("ollama", False) is True


def test_egress_consent_cloud_requires_yes_in_non_interactive(monkeypatch):
    # assume_yes bypasses the prompt
    assert ai.egress_consent("anthropic", True) is True
    # non-interactive without assume_yes must refuse (never silently sends)
    monkeypatch.setattr(ai.sys.stdin, "isatty", lambda: False)
    assert ai.egress_consent("openai", False) is False


def test_llm_narrative_unknown_provider_returns_none_not_raises():
    # No network; unknown provider is caught and returns None so the audit
    # always completes on the deterministic engine.
    assert ai.llm_narrative({"profile": "generic"}, provider="bogus-provider") is None


def test_llm_narrative_cloud_without_key_returns_none():
    assert ai.llm_narrative({"profile": "generic"}, provider="anthropic", api_key=None) is None
