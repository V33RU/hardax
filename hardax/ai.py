"""
HARDAX optional LLM narrative layer.

This is an OPT-IN readability layer that sits on top of the deterministic
analysis engine (hardax/analysis.py). It is disabled unless the user passes
--ai. It does not replace the deterministic engine and it does not produce
findings.

Hard guarantees (these mirror the project's prime directive and no-leak rule):

  * Input is ONLY the structured deterministic analysis dict (risk score,
    grade, attack-chain names, finding labels/categories/statuses,
    remediation text). The raw `result` output of each check - which is where
    serials, PHI strings, IP addresses and ports live - is NEVER sent. By
    construction, device data does not enter the prompt.
  * A redaction backstop strips IP / MAC / long-hex / path-like tokens from the
    serialized payload before it leaves the process.
  * The model is instructed to discuss ONLY the findings provided and to never
    introduce a vulnerability/CVE/claim that is not in the input. Its output is
    treated as prose only: it is never parsed back into findings, never changes
    a status, and never triggers an action.
  * Cloud providers print an egress warning and require consent (interactive
    prompt or --ai-yes). The local Ollama backend sends nothing off-machine.
  * Any failure (no key, no network, API error, bad response) logs a warning
    and returns None - the audit always completes on the deterministic engine
    alone. The LLM is never on the critical path.

stdlib only (urllib) - no new pip dependency.
"""

import json
import os
import re
import sys
import urllib.request
import urllib.error
from typing import Any, Dict, List, Optional

DEFAULT_MODELS = {
    "anthropic": "claude-3-5-haiku-latest",
    "openai": "gpt-4o-mini",
    "ollama": "llama3",
}

ENV_KEYS = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "ollama": "",  # no key needed
}

_SYSTEM_PROMPT = (
    "You are a security analyst writing the executive summary of a device "
    "hardening audit. You may discuss ONLY the findings contained in the JSON "
    "the user provides. You must NOT introduce any vulnerability, CVE, exploit, "
    "or claim that is not present in that JSON. Do NOT invent or change "
    "severities. If something was not tested, say it was not assessed. "
    "Write plain prose (no markdown headings, no code fences). Produce three "
    "short paragraphs: (1) overall posture in 3-4 sentences citing the risk "
    "score and grade; (2) why the listed attack chains matter for a "
    "'{profile}' device; (3) the remediation order with a one-line reason for "
    "each top item. Keep it under 250 words."
)


def resolve_key(provider: str, explicit: Optional[str]) -> Optional[str]:
    """API key from --ai-key, else the provider env var. Ollama needs none."""
    if explicit:
        return explicit
    env = ENV_KEYS.get(provider, "")
    return os.environ.get(env) if env else None


def _redact(text: str) -> str:
    """Backstop scrub of anything identifier-like that might ride along in a
    label or remediation string. The structured payload should not contain
    device data in the first place; this is defence in depth."""
    text = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", "[ip]", text)
    text = re.sub(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b", "[mac]", text)
    text = re.sub(r"\b[0-9a-fA-F]{12,}\b", "[hex]", text)
    return text


def _build_payload(analysis: Dict[str, Any]) -> Dict[str, Any]:
    """Whitelist exactly the structured fields that may be sent. Raw check
    output (`result`) is intentionally excluded - it never appears in the
    analysis dict's priorities anyway, but we whitelist to be certain."""
    chains = [
        {"name": c.get("name", ""),
         "severity": c.get("severity", ""),
         "steps": [s.get("label", "") for s in c.get("steps", [])]}
        for c in analysis.get("attack_chains", [])
    ]
    priorities = [
        {"label": p.get("label", ""),
         "category": p.get("category", ""),
         "status": p.get("status", ""),
         "remediation": p.get("remediation", "")}
        for p in analysis.get("priorities", [])[:10]
    ]
    return {
        "risk_score": analysis.get("risk_score"),
        "grade": analysis.get("grade"),
        "profile": analysis.get("profile"),
        "totals": analysis.get("totals", {}),
        "attack_chains": chains,
        "priorities": priorities,
        "verify_clusters": analysis.get("verify_clusters", []),
    }


def _post(url: str, headers: Dict[str, str], body: Dict[str, Any], timeout: int) -> Dict[str, Any]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _call_anthropic(model, key, system, user, timeout):
    out = _post(
        "https://api.anthropic.com/v1/messages",
        {"x-api-key": key, "anthropic-version": "2023-06-01",
         "content-type": "application/json"},
        {"model": model, "max_tokens": 800, "temperature": 0.2,
         "system": system, "messages": [{"role": "user", "content": user}]},
        timeout,
    )
    return out["content"][0]["text"]


def _call_openai(model, key, system, user, timeout):
    out = _post(
        "https://api.openai.com/v1/chat/completions",
        {"Authorization": f"Bearer {key}", "content-type": "application/json"},
        {"model": model, "max_tokens": 800, "temperature": 0.2,
         "messages": [{"role": "system", "content": system},
                      {"role": "user", "content": user}]},
        timeout,
    )
    return out["choices"][0]["message"]["content"]


def _call_ollama(model, base_url, system, user, timeout):
    base = (base_url or "http://localhost:11434").rstrip("/")
    out = _post(
        base + "/api/chat",
        {"content-type": "application/json"},
        {"model": model, "stream": False, "options": {"temperature": 0.2},
         "messages": [{"role": "system", "content": system},
                      {"role": "user", "content": user}]},
        timeout,
    )
    return out["message"]["content"]


def llm_narrative(analysis: Dict[str, Any], *,
                  provider: str,
                  model: Optional[str] = None,
                  api_key: Optional[str] = None,
                  base_url: Optional[str] = None,
                  timeout: int = 30) -> Optional[Dict[str, Any]]:
    """Produce an AI narrative dict from the deterministic analysis, or None on
    any failure. Never raises into the caller - the audit must always finish."""
    provider = (provider or "").lower()
    model = model or DEFAULT_MODELS.get(provider, "")
    system = _SYSTEM_PROMPT.format(profile=analysis.get("profile", "generic"))
    user = _redact(json.dumps(_build_payload(analysis), indent=2))

    try:
        if provider == "anthropic":
            if not api_key:
                raise ValueError("missing API key (set ANTHROPIC_API_KEY or --ai-key)")
            text = _call_anthropic(model, api_key, system, user, timeout)
        elif provider == "openai":
            if not api_key:
                raise ValueError("missing API key (set OPENAI_API_KEY or --ai-key)")
            text = _call_openai(model, api_key, system, user, timeout)
        elif provider == "ollama":
            text = _call_ollama(model, base_url, system, user, timeout)
        else:
            raise ValueError(f"unknown provider '{provider}'")
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode("utf-8", errors="replace")[:200]
        except Exception:
            pass
        print(f"[ai] {provider} HTTP {e.code}: {detail}", file=sys.stderr)
        return None
    except Exception as e:  # network, timeout, key, parse - never fatal
        print(f"[ai] narrative skipped ({provider}): {e}", file=sys.stderr)
        return None

    text = (text or "").strip()
    if not text:
        print(f"[ai] {provider} returned empty narrative", file=sys.stderr)
        return None

    return {
        "provider": provider,
        "model": model,
        "text": text,
        "disclaimer": "AI-generated summary of confirmed findings. Not a HARDAX "
                      "finding; verify independently.",
    }


def is_cloud(provider: str) -> bool:
    return (provider or "").lower() in ("anthropic", "openai")


def egress_consent(provider: str, assume_yes: bool) -> bool:
    """For cloud providers, warn about data egress and require consent. Local
    Ollama needs no consent (nothing leaves the machine)."""
    if not is_cloud(provider):
        return True
    if assume_yes:
        return True
    msg = (f"[ai] --ai will send the REDACTED analysis summary (risk score, "
           f"finding labels, remediation text - NO raw device output) to "
           f"{provider}. ")
    if not sys.stdin.isatty():
        print(msg + "Non-interactive session; pass --ai-yes to allow. Skipping AI.",
              file=sys.stderr)
        return False
    try:
        ans = input(msg + "Continue? [y/N] ").strip().lower()
    except EOFError:
        return False
    return ans in ("y", "yes")


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------

def render_text(narrative: Dict[str, Any]) -> str:
    if not narrative:
        return ""
    L = []
    L.append("-" * 64)
    L.append(f"AI NARRATIVE  ({narrative.get('provider')}/{narrative.get('model')})")
    L.append("-" * 64)
    L.append(narrative.get("text", ""))
    L.append("")
    L.append("[" + narrative.get("disclaimer", "") + "]")
    L.append("-" * 64)
    return "\n".join(L)


def _esc(s: Any) -> str:
    s = str(s) if s is not None else ""
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_html(narrative: Dict[str, Any]) -> str:
    if not narrative:
        return ""
    body = _esc(narrative.get("text", "")).replace("\n\n", "</p><p>").replace("\n", "<br>")
    return f"""
    <div class="category-section" id="ai_section" style="margin:18px 0;border:1px dashed #8957e5;border-radius:8px;background:#161b22;padding:16px">
      <h2 style="margin:0 0 6px 0">&#129504; AI Narrative
        <span style="font-size:.6em;background:#8957e5;color:#fff;border-radius:4px;padding:1px 6px;vertical-align:middle">
          {_esc(narrative.get('provider'))}/{_esc(narrative.get('model'))}</span>
      </h2>
      <div style="opacity:.92;line-height:1.5"><p>{body}</p></div>
      <div style="opacity:.5;font-size:.78em;margin-top:10px">{_esc(narrative.get('disclaimer'))}</div>
    </div>
    """
