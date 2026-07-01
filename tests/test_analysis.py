"""Tests for the deterministic analysis engine (hardax/analysis.py)."""
from hardax import analysis


def _row(label, status, category="ADB_SECURITY"):
    return {"category": category, "label": label, "status": status,
            "id": "", "remediation": ""}


def test_clean_device_scores_zero_grade_a():
    a = analysis.analyze_findings([], {"critical": 0, "warning": 0, "verify": 0})
    assert a["risk_score"] == 0 and a["grade"] == "A"
    assert a["attack_chains"] == [] and a["priorities"] == []


def test_risk_score_is_monotonic_and_bounded():
    s1 = analysis.analyze_findings([], {"critical": 1})["risk_score"]
    s5 = analysis.analyze_findings([], {"critical": 5})["risk_score"]
    s20 = analysis.analyze_findings([], {"critical": 20})["risk_score"]
    assert 0 < s1 < s5 < s20 <= 100


def test_grade_boundaries():
    assert analysis._grade(0) == "A"
    assert analysis._grade(100) == "F"
    # grade should worsen monotonically as score rises
    grades = [analysis._grade(s) for s in (10, 25, 40, 60, 90)]
    assert grades == ["A", "B", "C", "D", "F"]


def test_attack_chain_requires_all_evidence_groups():
    # Only the "network adb" half of the chain is present -> no chain fires.
    partial = [_row("ADB Over Network configured", "WARNING")]
    a = analysis.analyze_findings(partial, {"warning": 1})
    assert a["attack_chains"] == []

    # Add the "root shell" half -> the chain now fires.
    full = partial + [_row("ADB Shell Running As Root", "CRITICAL")]
    a = analysis.analyze_findings(full, {"warning": 1, "critical": 1})
    names = [c["name"].lower() for c in a["attack_chains"]]
    assert any("network adb" in n for n in names)


def test_safe_rows_never_produce_chains_or_priorities():
    # SAFE rows are not risk statuses, so they must not be treated as evidence.
    rows = [_row("ADB Over Network configured", "SAFE"),
            _row("ADB Shell Running As Root", "SAFE")]
    a = analysis.analyze_findings(rows, {"safe": 2})
    assert a["attack_chains"] == [] and a["priorities"] == []


def test_priorities_rank_critical_above_warning():
    rows = [_row("Some Warning Finding", "WARNING", "NETWORK"),
            _row("Some Critical Finding", "CRITICAL", "NETWORK")]
    a = analysis.analyze_findings(rows, {"critical": 1, "warning": 1})
    labels = [p["label"] for p in a["priorities"]]
    assert labels.index("Some Critical Finding") < labels.index("Some Warning Finding")


def test_output_is_serialisable_and_has_expected_keys():
    a = analysis.analyze_findings([_row("x", "CRITICAL")], {"critical": 1}, profile="pos")
    for key in ("risk_score", "grade", "posture", "profile", "totals",
                "attack_chains", "priorities", "verify_clusters", "method"):
        assert key in a
    assert a["profile"] == "pos"
    # renderers work
    assert isinstance(analysis.render_text(a), str)
    assert "<div" in analysis.render_html(a)


def test_unknown_profile_falls_back_to_generic():
    a = analysis.analyze_findings([], {}, profile="does-not-exist")
    assert a["profile"] == "generic"
