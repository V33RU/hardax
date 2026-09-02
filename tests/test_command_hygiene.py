"""Shell-level hygiene invariants for the bundled check commands.

Each test here encodes a defect class that shipped in a real release and had
to be found by hand. They are cheap to run and they stop the same shape of
bug coming back.
"""
import re
import shutil
import subprocess
from collections import Counter, defaultdict

import pytest

from conftest import load_all_checks

FAILABLE = ("critical", "high", "warning", "medium")

# safe_patterns that match any non-empty output. Legitimate on an evidence
# collector (info / verify), a bug on a check that is supposed to fail.
ALWAYS_MATCH = {".", ".*", "^.*$", "(?s).*", ".+", "^.+$"}


def _fmt(checks):
    return "\n".join(f"  {c['_file']} [{c['level']}] {c['label']}" for c in checks)


@pytest.mark.skipif(not shutil.which("sh"), reason="POSIX sh not available")
def test_every_command_parses_under_posix_sh():
    """`$((cmd ...)` is read as arithmetic expansion, not a subshell, so the
    whole script fails to parse and the shell error becomes the check result.
    That shipped in ADB-* and scored CRITICAL on every device."""
    broken = []
    for c in load_all_checks():
        proc = subprocess.run(["sh", "-n"], input=c["command"],
                              capture_output=True, text=True)
        if proc.returncode != 0:
            broken.append(f"  {c['_file']} [{c['label']}]: {proc.stderr.strip()}")
    assert not broken, "commands that do not parse under POSIX sh:\n" + "\n".join(broken)


def test_failable_checks_redirect_stderr_on_optional_path_reads():
    """The engine concatenates stderr into the command result. A `cat` on a
    path that may not exist therefore puts 'No such file or directory' into
    the output, which fails the safe_pattern and scores a finding on a device
    that is not actually misconfigured."""
    # consume every path argument so a multi-path read is judged on the
    # redirect that follows the last one, not the first
    reader = re.compile(
        r"\b(?:cat|zcat|gzip -dc|head|tail)"
        r"(?:\s+(?:/proc|/sys|/data|/vendor|/system|/dev)[^\s|;&)]*)+")
    offenders = []
    for c in load_all_checks():
        if c["level"] not in FAILABLE:
            continue
        for m in reader.finditer(c["command"]):
            tail = c["command"][m.end():]
            # the redirect must appear before the pipeline segment ends
            segment = re.split(r"[|;&)]", tail, 1)[0]
            if "2>" not in segment:
                offenders.append(f"  {c['_file']} [{c['label']}]: {m.group(0)}")
    assert not offenders, (
        "failable checks reading an optional path without redirecting stderr:\n"
        + "\n".join(offenders))


def test_failable_checks_are_capable_of_failing():
    """A check at critical/high/warning/medium whose safe_pattern matches any
    output can never produce a finding. It inflates the check count and tells
    the auditor nothing."""
    dead = [c for c in load_all_checks()
            if c["level"] in FAILABLE and c["safe_pattern"] in ALWAYS_MATCH]
    assert not dead, "failable checks that can never fail:\n" + _fmt(dead)


def test_no_two_checks_share_a_command():
    """Two checks running the identical command are the same check twice."""
    by_cmd = defaultdict(list)
    for c in load_all_checks():
        by_cmd[c["command"]].append(c)
    dups = {k: v for k, v in by_cmd.items() if len(v) > 1}
    msg = "\n\n".join(f"  command: {k[:100]}\n" + _fmt(v) for k, v in dups.items())
    assert not dups, "checks sharing an identical command:\n" + msg


def test_labels_are_not_confusable():
    """'Paired Device Count' and 'Paired Devices Count' both shipped, running
    the same pipeline. Labels are the report's primary key, so near-identical
    ones are indistinguishable to a reader."""
    norm = defaultdict(list)
    for c in load_all_checks():
        key = re.sub(r"[^a-z0-9]", "", c["label"].lower())
        key = re.sub(r"s$", "", key)
        norm[key].append(c)
    dups = {k: v for k, v in norm.items() if len(v) > 1}
    msg = "\n\n".join(f"  normalised: {k}\n" + _fmt(v) for k, v in dups.items())
    assert not dups, "labels that normalise to the same string:\n" + msg


def test_kernel_config_patterns_use_lowercase_y():
    """Kernel config values are lowercase. `CONFIG_SECCOMP=Y` shipped and
    could never match, so the check silently never passed."""
    bad = [c for c in load_all_checks()
           if re.search(r"CONFIG_[A-Z0-9_]+=Y\b", c["safe_pattern"])]
    assert not bad, "safe_patterns matching an uppercase =Y:\n" + _fmt(bad)


def test_config_gz_checks_report_when_unobservable():
    """/proc/config.gz needs CONFIG_IKCONFIG_PROC and is absent on most
    production Android builds. A check that reads it must say so rather than
    returning empty, and must accept that state as passing."""
    missing = []
    for c in load_all_checks():
        if "config.gz" not in c["command"] or c["level"] not in FAILABLE:
            continue
        # either an explicit NOT_OBSERVABLE verdict the safe_pattern accepts,
        # or a readability guard that branches to its own worded fallback
        declares = ("NOT_OBSERVABLE" in c["command"]
                    and "NOT_OBSERVABLE" in c["safe_pattern"])
        guards = re.search(r"\[\s+!?\s*-[re]\s+/proc/config\.gz\s+\]", c["command"])
        if not declares and not guards:
            missing.append(c)
    assert not missing, (
        "config.gz checks that do not report NOT_OBSERVABLE:\n" + _fmt(missing))


def test_every_check_has_remediation_text():
    missing = [c for c in load_all_checks() if not c.get("remediation", "").strip()]
    assert not missing, "checks without remediation:\n" + _fmt(missing)


def test_no_em_dashes_in_check_text():
    """House style: hyphens, never em dashes."""
    bad = []
    for c in load_all_checks():
        for field in ("label", "description", "remediation", "why", "risk_if_fail"):
            if "\u2014" in (c.get(field) or ""):
                bad.append(f"  {c['_file']} [{c['label']}]: em dash in {field}")
    assert not bad, "em dashes found:\n" + "\n".join(bad)


def test_category_set_is_intact():
    """The exact check total is already pinned by the README badge test, so
    this guards the shape instead: no category may silently empty out, and a
    category must not shrink to a single check without being noticed."""
    counts = Counter(c["category"] for c in load_all_checks())
    assert len(counts) == 28, f"category count changed: {sorted(counts)}"
    thin = {cat: n for cat, n in counts.items() if n < 3}
    assert not thin, f"categories reduced to almost nothing: {thin}"
