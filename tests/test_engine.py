"""Tests for the check-execution/classification engine (runChecks) and the
baseline tamper-detection logic."""
import hardax
from conftest import FakeDevice, make_check


# --- status classification matrix -----------------------------------------

def test_match_is_safe(run_check):
    row, counts = run_check(make_check(safe_pattern="^ok$", level="critical"), "ok")
    assert row["status"] == "SAFE" and counts["safe"] == 1


def test_no_match_critical_is_critical(run_check):
    row, counts = run_check(make_check(safe_pattern="^ok$", level="critical"), "BAD")
    assert row["status"] == "CRITICAL" and counts["critical"] == 1


def test_no_match_warning_is_warning(run_check):
    row, counts = run_check(make_check(safe_pattern="^ok$", level="warning"), "BAD")
    assert row["status"] == "WARNING" and counts["warning"] == 1


def test_no_match_info_is_info(run_check):
    row, _ = run_check(make_check(safe_pattern="^ok$", level="info"), "BAD")
    assert row["status"] == "INFO"


def test_empty_with_empty_is_safe(run_check):
    row, _ = run_check(make_check(safe_pattern="^x$", level="critical", empty_is_safe=True), "")
    assert row["status"] == "SAFE"


def test_empty_critical_becomes_verify(run_check):
    row, counts = run_check(make_check(safe_pattern="^x$", level="critical"), "")
    assert row["status"] == "VERIFY" and counts["verify"] == 1


def test_empty_info_becomes_info(run_check):
    row, _ = run_check(make_check(safe_pattern="^x$", level="info"), "")
    assert row["status"] == "INFO"


def test_null_with_null_is_safe(run_check):
    row, _ = run_check(make_check(safe_pattern="^x$", level="critical", null_is_safe=True), "null")
    assert row["status"] == "SAFE"


def test_null_without_flag_is_verify(run_check):
    row, _ = run_check(make_check(safe_pattern="^x$", level="critical"), "null")
    assert row["status"] == "VERIFY"


def test_transport_error_is_skipped(run_check):
    row, counts = run_check(make_check(level="critical"), "device offline")
    assert row["status"] == "SKIPPED" and counts["skipped"] == 1


def test_service_error_is_skipped(run_check):
    row, counts = run_check(make_check(level="critical"), "cmd: can't find service")
    assert row["status"] == "SKIPPED" and counts["skipped"] == 1


def test_counts_sum_equals_number_of_checks():
    checks = [make_check(safe_pattern="^ok$")] * 5
    rows, counts = hardax.runChecks(FakeDevice(default="ok"), checks)
    assert len(rows) == 5 and sum(counts.values()) == 5


def test_row_has_expected_shape(run_check):
    row, _ = run_check(make_check(remediation="do x"), "anything")
    for key in ("category", "label", "status", "command", "result",
                "description", "baseline", "remediation"):
        assert key in row


def test_row_carries_technical_metadata(run_check):
    chk = make_check(id="X-1", why="w-text", risk_if_fail="r-text", nist_800_53="AC-3",
                     cis_id="1.1", tags=["a", "b"], expected_secure_state="ok-state")
    row, _ = run_check(chk, "anything")
    assert row["id"] == "X-1" and row["why"] == "w-text" and row["risk_if_fail"] == "r-text"
    assert row["nist_800_53"] == "AC-3" and row["cis_id"] == "1.1"
    assert row["tags"] == ["a", "b"] and row["expected_secure_state"] == "ok-state"


# --- baseline tamper detection --------------------------------------------

BKEY_CHECK = make_check(id="BASE", baseline_key="k",
                        safe_pattern="^[a-f0-9]+$", level="info")


def test_baseline_save_records_value():
    bv = {}
    rows, _ = hardax.runChecks(FakeDevice(default="abc123"), [dict(BKEY_CHECK)],
                               baseline_mode="save", baseline_values=bv)
    assert bv["k"] == "abc123"
    assert rows[0]["status"] == "SAFE" and rows[0]["baseline"] == "recorded"


def test_baseline_compare_match():
    rows, _ = hardax.runChecks(FakeDevice(default="abc123"), [dict(BKEY_CHECK)],
                               baseline_mode="compare", baseline_values={"k": "abc123"})
    assert rows[0]["status"] == "SAFE" and rows[0]["baseline"] == "match"


def test_baseline_compare_mismatch_is_critical():
    rows, counts = hardax.runChecks(FakeDevice(default="deadbeef"), [dict(BKEY_CHECK)],
                                    baseline_mode="compare", baseline_values={"k": "abc123"})
    assert rows[0]["status"] == "CRITICAL" and rows[0]["baseline"] == "mismatch"
    assert counts["critical"] == 1


def test_baseline_unreadable_is_critical_fail_closed():
    # baseline HAS the value but the device returns nothing -> tamper/evasion
    rows, counts = hardax.runChecks(FakeDevice(default=""), [dict(BKEY_CHECK)],
                                    baseline_mode="compare", baseline_values={"k": "abc123"})
    assert rows[0]["status"] == "CRITICAL" and rows[0]["baseline"] == "unreadable"
    assert counts["critical"] == 1


def test_baseline_missing_key_is_verify():
    rows, _ = hardax.runChecks(FakeDevice(default="abc123"), [dict(BKEY_CHECK)],
                               baseline_mode="compare", baseline_values={})
    assert rows[0]["status"] == "VERIFY" and rows[0]["baseline"] == "missing"


def test_baseline_file_roundtrip(tmp_path):
    p = str(tmp_path / "baseline.json")
    hardax._saveBaseline(p, {"model": "M", "fingerprint": "fp1"}, {"k": "v"})
    doc = hardax._loadBaseline(p)
    assert doc["values"] == {"k": "v"}
    assert doc["device"]["fingerprint"] == "fp1"
    assert doc["hardax_baseline"] == "1"
