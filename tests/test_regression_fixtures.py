"""Replay recorded device output through the real shipped checks.

Every case here is a status a real device produced, or the exact output a
past defect produced. The check definition is loaded from the shipped
commands/*.json rather than synthesised, so a safe_pattern or level edit
that would reintroduce a fixed false positive fails this suite.

To add a case: append to tests/fixtures/device_outputs.json as
  "<check label>": [[ "<raw output>", "<EXPECTED STATUS>", "<why>" ], ...]
"""
import os
import json

import pytest

import hardax
from conftest import FakeDevice, COMMANDS_DIR, load_all_checks

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "fixtures", "device_outputs.json")


def _fixtures():
    with open(FIXTURES, encoding="utf-8") as fh:
        return json.load(fh)


def _by_label():
    return {c["label"]: c for c in load_all_checks()}


def _cases():
    """Flatten to (label, output, expected, why) so each is its own test."""
    out = []
    for label, cases in _fixtures().items():
        for output, expected, why in cases:
            out.append(pytest.param(label, output, expected, why,
                                    id=f"{label[:40]}::{expected}::{output[:28] or 'EMPTY'}"))
    return out


def test_every_fixture_label_still_exists():
    """A renamed or deleted check must not silently drop its regression cases."""
    known = set(_by_label())
    missing = sorted(set(_fixtures()) - known)
    assert not missing, (
        "fixtures reference checks that no longer exist (renamed or removed):\n  "
        + "\n  ".join(missing))


@pytest.mark.parametrize("label,output,expected,why", _cases())
def test_recorded_output_classifies_as_expected(label, output, expected, why):
    check = _by_label()[label]
    dev = FakeDevice(default=output)
    rows, _ = hardax.runChecks(dev, [check])
    got = rows[0]["status"]
    assert got == expected, (
        f"\n  check    : {label}"
        f"\n  output   : {output!r}"
        f"\n  expected : {expected}"
        f"\n  got      : {got}"
        f"\n  pattern  : {check['safe_pattern']!r}  level={check['level']}"
        f"  empty_is_safe={check.get('empty_is_safe', False)}"
        f"\n  why this case exists: {why}")


def test_fixture_corpus_covers_the_fixed_false_positives():
    """Guards the guard: every check whose defect we fixed must keep a case."""
    required = [
        "Network ADB Bound To Loopback Only",   # $(( parsed as arithmetic
        "Kernel Stack Protector (Strong)",      # zcat stderr became the result
        "Kernel Hardening (PAN/UAO)",           # same
        "SECCOMP Kernel Support",               # CONFIG_SECCOMP=Y could never match
        "Security Patch Level",                 # date -d fallback to epoch 0
        "Protected Symlinks Enabled",           # unredirected cat on a sysctl
        "Writable System Partition",            # grep '/system' matched /system_ext
        "Block Devices World-Readable",         # counted symlinks and directories
        "Writable Paths in $PATH",              # xargs -I unsupported by toybox
        "Private Keys Exposed",                 # matched *.pem by name
    ]
    have = set(_fixtures())
    missing = [r for r in required if r not in have]
    assert not missing, "regression cases removed for previously fixed defects:\n  " + "\n  ".join(missing)


def test_each_fixture_has_both_a_passing_and_failing_case_where_possible():
    """A check pinned only by its passing case would not notice a pattern
    widened to match everything."""
    fx = _fixtures()
    by_label = _by_label()
    one_sided = []
    for label, cases in fx.items():
        check = by_label.get(label)
        if not check or check["level"] not in ("critical", "high", "warning", "medium"):
            continue  # info/verify checks have no meaningful failing case
        statuses = {c[1] for c in cases}
        if not (statuses & {"CRITICAL", "WARNING"}):
            one_sided.append(f"{label} (only {sorted(statuses)})")
    assert not one_sided, (
        "failable checks pinned only by passing cases:\n  " + "\n  ".join(one_sided))
