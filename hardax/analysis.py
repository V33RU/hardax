"""
HARDAX deterministic post-audit analysis.

This module turns the raw per-check results that runChecks() produces into a
prioritised, human-readable risk picture: a 0-100 risk score, correlated
attack chains, a ranked remediation list, and a triage of the manual-VERIFY
items.

Design constraints (these mirror the project's prime directive):

  * It operates ONLY on findings HARDAX already produced. It never runs a
    command on the device, never contacts the network, and never invents a
    finding.
  * Every attack chain and every priority cites confirmed result rows by
    label. If the supporting rows are not present in a risk state, the chain
    does not fire. There is no model, no guess, no probability of a finding
    that was not actually observed.
  * It is fully offline and deterministic: the same input rows always produce
    the same output. No LLM, no external dependency, stdlib only.

The output is a plain dict so it can be embedded in the JSON report, rendered
into the HTML report, or printed in the terminal summary.
"""

from typing import Any, Dict, List, Optional

# Statuses that represent an actual finding (as opposed to SAFE / INFO /
# SKIPPED). VERIFY is included where noted because it means "manual review
# required", which is a weaker but real signal.
RISK_STATUSES = ("CRITICAL", "WARNING")


def _norm(s: Any) -> str:
    return (str(s) if s is not None else "").strip().lower()


def _status(row: Dict[str, Any]) -> str:
    return (row.get("status") or "").upper()


def _matching(rows: List[Dict[str, Any]], needles, statuses=RISK_STATUSES) -> List[Dict[str, Any]]:
    """Rows whose label or id contains any needle (case-insensitive) AND whose
    status is in `statuses`. This is the only way chains and priorities select
    evidence, so a chain can never reference a check that did not fire."""
    out = []
    for r in rows:
        if _status(r) not in statuses:
            continue
        hay = _norm(r.get("label")) + " " + _norm(r.get("id"))
        if any(_norm(n) in hay for n in needles):
            out.append(r)
    return out


# ---------------------------------------------------------------------------
# Risk score
# ---------------------------------------------------------------------------

def _risk_score(counts: Dict[str, int]) -> int:
    """Composite 0-100 risk score (higher = worse).

    Modelled as a saturating hazard so the score grows with diminishing
    returns instead of pegging at 100 the moment a couple of criticals appear:

        hazard = 1 - (0.88^critical) * (0.97^warning) * (0.995^verify)

    1 critical  ~= 12,  3 ~= 32,  5 ~= 47,  10 ~= 72,  20 ~= 92.
    A device with no critical/warning/verify findings scores 0.
    """
    c = int(counts.get("critical", 0) or 0)
    w = int(counts.get("warning", 0) or 0)
    v = int(counts.get("verify", 0) or 0)
    hazard = 1.0 - (0.88 ** c) * (0.97 ** w) * (0.995 ** v)
    return max(0, min(100, round(hazard * 100)))


def _grade(score: int) -> str:
    if score <= 15:
        return "A"
    if score <= 30:
        return "B"
    if score <= 50:
        return "C"
    if score <= 75:
        return "D"
    return "F"


def _posture(score: int) -> str:
    if score <= 15:
        return "Strong - no significant findings"
    if score <= 30:
        return "Good - minor findings to review"
    if score <= 50:
        return "Fair - several findings need remediation"
    if score <= 75:
        return "Weak - multiple serious findings"
    return "Critical - severe exposure, remediate immediately"


# ---------------------------------------------------------------------------
# Attack-chain correlation
#
# Each chain lists "groups" of label/id needles. A chain fires only when EVERY
# group has at least one matching row in a risk status. The matched rows are
# carried into the output as evidence, so nothing is asserted that was not
# observed.
# ---------------------------------------------------------------------------

_CHAINS = [
    {
        "name": "Unauthenticated root foothold over network ADB",
        "severity": "critical",
        "impact": "An attacker on the same network reaches adbd and lands an "
                  "interactive root shell with no credentials.",
        "groups": [
            ["network adb", "adb over network"],
            ["adb shell running as root", "adb root access",
             "debuggable flag", "adb secure mode"],
        ],
    },
    {
        "name": "Persistent implant via writable system partition",
        "severity": "critical",
        "impact": "Verified boot / dm-verity is not enforcing, so a writable "
                  "system or vendor partition lets a planted binary survive "
                  "reboots.",
        "groups": [
            ["dm-verity", "disable-verity", "verified boot", "veritymode"],
            ["debuggable flag", "debug build type", "world-writable",
             "writable paths in $path"],
        ],
    },
    {
        "name": "Physical-access full image control via unlocked bootloader",
        "severity": "critical",
        "impact": "An unlocked / unlockable bootloader plus non-enforcing "
                  "verity lets someone with brief physical access flash a "
                  "modified image.",
        "groups": [
            ["oem unlock", "fastboot unlock", "bootloader"],
            ["dm-verity", "disable-verity", "veritymode"],
        ],
    },
    {
        "name": "Keystroke / credential exfiltration",
        "severity": "warning",
        "impact": "A third-party or network-capable keyboard combined with an "
                  "enabled accessibility service can capture and exfiltrate "
                  "everything typed (PINs, passwords, PAN, PHI).",
        "groups": [
            ["3rd party keyboard", "imes holding internet", "input method",
             "third party"],
            ["accessibility services enabled"],
        ],
    },
    {
        "name": "PHI / sensitive data has an egress path",
        "severity": "critical",
        "impact": "Unprotected sensitive data on disk plus an open egress "
                  "(cloud backup, network ADB, or a service on all interfaces) "
                  "means the data can leave the device.",
        "groups": [
            ["unencrypted phi", "external storage phi", "log files with phi",
             "phi indicators"],
            ["backup enabled", "backup allowed", "adb over network",
             "listening on all interfaces", "open listening ports"],
        ],
    },
    {
        "name": "Exposed network service on a debuggable device",
        "severity": "warning",
        "impact": "A service listening on all interfaces on a device that is "
                  "still debuggable broadens the remote attack surface.",
        "groups": [
            ["listening on all interfaces", "open listening ports",
             "remote management", "remote desktop", "http server"],
            ["debuggable flag", "debug build type", "adb over network"],
        ],
    },
]


def _detect_chains(rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    fired = []
    for chain in _CHAINS:
        evidence = []
        ok = True
        for group in chain["groups"]:
            hits = _matching(rows, group)
            if not hits:
                ok = False
                break
            # carry one representative row per satisfied group
            evidence.extend(hits)
        if not ok:
            continue
        # de-duplicate evidence by label, preserve order
        seen = set()
        steps = []
        for r in evidence:
            lbl = r.get("label", "?")
            if lbl in seen:
                continue
            seen.add(lbl)
            steps.append({
                "label": lbl,
                "category": r.get("category", ""),
                "status": _status(r),
            })
        fired.append({
            "name": chain["name"],
            "severity": chain["severity"],
            "impact": chain["impact"],
            "steps": steps,
            "confidence": "correlated from confirmed findings",
        })
    # critical chains first
    fired.sort(key=lambda c: 0 if c["severity"] == "critical" else 1)
    return fired


# ---------------------------------------------------------------------------
# Profile weighting + prioritisation
# ---------------------------------------------------------------------------

_PROFILE_BOOST = {
    "pos": {"POS_SECURITY", "NETWORK", "CRYPTOGRAPHY", "CERTIFICATE_AUDIT", "MALWARE"},
    "medical": {"MEDICAL", "PRIVACY", "STORAGE", "NETWORK", "CRYPTOGRAPHY"},
    "kiosk": {"BOOT_SECURITY", "ADB_SECURITY", "DEVICE_MANAGEMENT", "USB_SECURITY"},
    "automotive": {"AUTOMOTIVE", "NETWORK", "BOOT_SECURITY"},
    "iot": {"NETWORK", "ADB_SECURITY", "BOOT_SECURITY", "CVE_INDICATORS"},
    "generic": set(),
}

_STATUS_WEIGHT = {"CRITICAL": 100, "WARNING": 40, "VERIFY": 10}


def _prioritise(rows, chains, profile, limit=10):
    chain_labels = set()
    for c in chains:
        for s in c["steps"]:
            chain_labels.add(s["label"])
    boost_cats = _PROFILE_BOOST.get(profile, set())

    scored = []
    for r in rows:
        st = _status(r)
        if st not in ("CRITICAL", "WARNING"):
            continue
        score = _STATUS_WEIGHT.get(st, 0)
        lbl = r.get("label", "?")
        cat = (r.get("category") or "").upper()
        in_chain = lbl in chain_labels
        if in_chain:
            score += 50
        if cat in boost_cats:
            score += 15
        scored.append((score, r, in_chain))

    scored.sort(key=lambda t: t[0], reverse=True)
    out = []
    for rank, (score, r, in_chain) in enumerate(scored[:limit], start=1):
        out.append({
            "rank": rank,
            "label": r.get("label", "?"),
            "category": r.get("category", ""),
            "status": _status(r),
            "in_attack_chain": in_chain,
            "remediation": r.get("remediation") or r.get("description") or "",
        })
    return out


def _verify_clusters(rows):
    clusters = {}
    for r in rows:
        if _status(r) != "VERIFY":
            continue
        cat = r.get("category", "OTHER")
        clusters.setdefault(cat, []).append(r.get("label", "?"))
    out = []
    for cat, labels in sorted(clusters.items(), key=lambda kv: len(kv[1]), reverse=True):
        out.append({"category": cat, "count": len(labels), "labels": labels[:8]})
    return out


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def analyze_findings(rows: List[Dict[str, Any]],
                     counts: Dict[str, int],
                     device_info: Optional[Dict[str, str]] = None,
                     certs: Optional[List[Dict[str, Any]]] = None,
                     profile: str = "generic") -> Dict[str, Any]:
    """Produce the deterministic analysis dict from confirmed audit rows."""
    rows = rows or []
    counts = counts or {}
    profile = (profile or "generic").lower()
    if profile not in _PROFILE_BOOST:
        profile = "generic"

    score = _risk_score(counts)
    chains = _detect_chains(rows)
    priorities = _prioritise(rows, chains, profile)
    verify = _verify_clusters(rows)

    # Top risks = the highest-ranked critical/warning items, condensed
    top_risks = [
        {"label": p["label"], "category": p["category"], "status": p["status"]}
        for p in priorities[:5]
    ]

    # Expired / user-installed certs are a concrete additional signal
    cert_flags = []
    for c in (certs or []):
        if c.get("status") in ("EXPIRED", "USER_CERT"):
            cert_flags.append({"cn": c.get("cn", "?"), "status": c.get("status")})

    return {
        "schema": "hardax.analysis/1",
        "engine": "deterministic",
        "profile": profile,
        "risk_score": score,
        "grade": _grade(score),
        "posture": _posture(score),
        "totals": {
            "critical": int(counts.get("critical", 0) or 0),
            "warning": int(counts.get("warning", 0) or 0),
            "verify": int(counts.get("verify", 0) or 0),
            "safe": int(counts.get("safe", 0) or 0),
            "info": int(counts.get("info", 0) or 0),
            "skipped": int(counts.get("skipped", 0) or 0),
        },
        "top_risks": top_risks,
        "attack_chains": chains,
        "priorities": priorities,
        "verify_clusters": verify[:6],
        "certificate_flags": cert_flags[:10],
        "method": "Operates only on confirmed HARDAX findings. No commands run, "
                  "no network access, no inferred findings. Attack chains fire "
                  "only when every required confirmed finding is present.",
    }


# ---------------------------------------------------------------------------
# Renderers (plain string; colour-free so they work in TXT and HTML)
# ---------------------------------------------------------------------------

def render_text(a: Dict[str, Any]) -> str:
    """Plain-text analysis block for the TXT report."""
    L = []
    L.append("=" * 64)
    L.append("HARDAX ANALYSIS (deterministic, offline)")
    L.append("=" * 64)
    L.append(f"Risk score : {a['risk_score']}/100  (grade {a['grade']})")
    L.append(f"Posture    : {a['posture']}")
    L.append(f"Profile    : {a['profile']}")
    t = a["totals"]
    L.append(f"Findings   : {t['critical']} critical, {t['warning']} warning, "
             f"{t['verify']} verify")
    if a["attack_chains"]:
        L.append("")
        L.append("Attack chains (correlated from confirmed findings):")
        for c in a["attack_chains"]:
            L.append(f"  [{c['severity'].upper()}] {c['name']}")
            L.append(f"      impact: {c['impact']}")
            for s in c["steps"]:
                L.append(f"        - {s['status']}: {s['label']} ({s['category']})")
    if a["priorities"]:
        L.append("")
        L.append("Fix in this order:")
        for p in a["priorities"]:
            tag = " [chain]" if p["in_attack_chain"] else ""
            L.append(f"  {p['rank']:>2}. [{p['status']}] {p['label']} "
                     f"({p['category']}){tag}")
    if a["verify_clusters"]:
        L.append("")
        L.append("Manual VERIFY items by category:")
        for vc in a["verify_clusters"]:
            L.append(f"  {vc['count']:>3}  {vc['category']}")
    L.append("")
    L.append(a["method"])
    L.append("=" * 64)
    return "\n".join(L)


def _esc(s: Any) -> str:
    s = str(s) if s is not None else ""
    return (s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def render_html(a: Dict[str, Any]) -> str:
    """Self-contained HTML analysis card (inline styles so it renders even if
    the surrounding template CSS changes)."""
    grade_color = {
        "A": "#2ecc71", "B": "#7bd66b", "C": "#f1c40f",
        "D": "#e67e22", "F": "#e74c3c",
    }.get(a["grade"], "#888")

    chains_html = ""
    for c in a["attack_chains"]:
        sev_color = "#e74c3c" if c["severity"] == "critical" else "#e67e22"
        steps = "".join(
            f'<li><span style="color:{sev_color}">{_esc(s["status"])}</span> '
            f'{_esc(s["label"])} <em style="opacity:.6">({_esc(s["category"])})</em></li>'
            for s in c["steps"]
        )
        chains_html += (
            f'<div style="border-left:3px solid {sev_color};padding:8px 12px;margin:8px 0;background:#0d1117">'
            f'<div style="font-weight:700;color:{sev_color}">{_esc(c["name"])}</div>'
            f'<div style="opacity:.8;font-size:.9em;margin:4px 0">{_esc(c["impact"])}</div>'
            f'<ul style="margin:4px 0 0 0;padding-left:18px;font-size:.88em">{steps}</ul>'
            f'</div>'
        )
    if not chains_html:
        chains_html = '<div style="opacity:.6">No multi-finding attack chains correlated.</div>'

    prio_html = ""
    for p in a["priorities"]:
        tag = (' <span style="background:#e74c3c;color:#fff;border-radius:3px;'
               'padding:0 5px;font-size:.75em">CHAIN</span>') if p["in_attack_chain"] else ""
        st_color = "#e74c3c" if p["status"] == "CRITICAL" else "#e67e22"
        prio_html += (
            f'<tr><td style="text-align:right;opacity:.6">{p["rank"]}</td>'
            f'<td style="color:{st_color};font-weight:700">{_esc(p["status"])}</td>'
            f'<td>{_esc(p["label"])}{tag}</td>'
            f'<td style="opacity:.6">{_esc(p["category"])}</td></tr>'
        )
    if not prio_html:
        prio_html = '<tr><td colspan="4" style="opacity:.6">No critical or warning findings.</td></tr>'

    return f"""
    <div class="category-section" id="analysis_section" style="margin:18px 0;border:1px solid #30363d;border-radius:8px;background:#161b22;padding:16px">
      <div style="display:flex;align-items:center;gap:18px;flex-wrap:wrap">
        <div style="text-align:center;min-width:120px">
          <div style="font-size:2.6em;font-weight:800;color:{grade_color};line-height:1">{a['risk_score']}</div>
          <div style="opacity:.6;font-size:.8em">RISK / 100</div>
          <div style="font-size:1.4em;font-weight:700;color:{grade_color}">Grade {a['grade']}</div>
        </div>
        <div style="flex:1;min-width:240px">
          <h2 style="margin:0 0 4px 0">&#9656; HARDAX Analysis</h2>
          <div style="opacity:.85">{_esc(a['posture'])}</div>
          <div style="opacity:.6;font-size:.85em;margin-top:4px">
            Profile: {_esc(a['profile'])} &nbsp;|&nbsp;
            {a['totals']['critical']} critical, {a['totals']['warning']} warning,
            {a['totals']['verify']} verify
          </div>
        </div>
      </div>

      <h3 style="margin:16px 0 4px 0">Attack chains</h3>
      {chains_html}

      <h3 style="margin:16px 0 4px 0">Fix in this order</h3>
      <table style="width:100%;border-collapse:collapse;font-size:.9em">
        <thead><tr style="opacity:.6;text-align:left">
          <th style="text-align:right">#</th><th>Severity</th><th>Finding</th><th>Category</th>
        </tr></thead>
        <tbody>{prio_html}</tbody>
      </table>

      <div style="opacity:.5;font-size:.78em;margin-top:12px">{_esc(a['method'])}</div>
    </div>
    """
