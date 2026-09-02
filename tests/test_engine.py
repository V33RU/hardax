"""Tests for the check-execution/classification engine (runChecks) and the
baseline tamper-detection logic."""
import io
import contextlib

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


# --- non-tty progress logging (CI / redirected / nohup runs) ---------------
#
# pytest captures stdout with a non-tty stream, so runChecks naturally takes
# the "else" (not _stdoutIsTty) branch here - this exercises exactly the
# redirected/logged scenario a real CI pipeline or `nohup hardax > log` hits.

def test_non_tty_progress_prints_clean_lines_not_carriage_returns():
    checks = [make_check(label=f"chk{i}", safe_pattern=".") for i in range(20)]
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        hardax.runChecks(FakeDevice(default="ok"), checks)
    out = buf.getvalue()
    assert "\r" not in out
    lines = [l for l in out.splitlines() if l.strip().startswith("[")]
    assert lines, "expected at least one progress line"
    assert lines[-1].startswith("[20/20]") or "[20/20]" in lines[-1]
    assert "safe=" in lines[0] and "critical=" in lines[0]


def test_non_tty_progress_line_count_is_bounded_for_large_check_sets():
    # One line per whole percent (plus a guaranteed final line), not one line
    # per check - a 767-check audit should log ~100 lines, not 767+.
    checks = [make_check(label=f"chk{i}", safe_pattern=".") for i in range(767)]
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        hardax.runChecks(FakeDevice(default="ok"), checks)
    lines = [l for l in buf.getvalue().splitlines() if l.strip().startswith("[")]
    assert 90 <= len(lines) <= 110
    assert lines[-1].startswith("[767/767]") or "[767/767]" in lines[-1]


# --- HUD dashboard terminal-fit checks --------------------------------------

def test_hud_fits_terminal_requires_both_width_and_height(monkeypatch):
    hud = hardax.HUDDashboard([{"category": "C"}] * 5, deviceInfo="d")
    required_width = hud._W + 4
    required_height = hud.panelHeight + 1

    # Wide enough and tall enough -> fits
    monkeypatch.setattr(hardax.Terminal, "getSize", staticmethod(lambda: (required_width, required_height)))
    assert hud.fitsTerminal() is True

    # Tall enough but too narrow -> must NOT fit (previously ignored width entirely)
    monkeypatch.setattr(hardax.Terminal, "getSize", staticmethod(lambda: (required_width - 1, required_height)))
    assert hud.fitsTerminal() is False

    # Wide enough but too short -> must not fit
    monkeypatch.setattr(hardax.Terminal, "getSize", staticmethod(lambda: (required_width, required_height - 1)))
    assert hud.fitsTerminal() is False


# --- network fallback executor --------------------------------------------

def test_fallback_executor_does_not_mangle_scripts_that_mention_netstat():
    """executeWithFallback rewrites the text before the first "|" and runs it
    alone to try su / drop -p / swap tool. On a shell script the first "|" is
    the first character of "||", so the base became an unterminated "if" and
    the device got a syntax error instead of the check.

    ADB-002 shipped this way: the command was
        P=$(getprop service.adb.tcp.port); if [ -z "$P" ] || [ "$P" = "0" ]; ...
    and the device received only
        P=$(getprop service.adb.tcp.port); if [ -z "$P" ]
    """
    script = ('P=$(getprop service.adb.tcp.port 2>/dev/null); '
              'if [ -z "$P" ] || [ "$P" = "0" ]; then echo DISABLED; '
              'else netstat -tln 2>/dev/null | grep ":$P"; fi')
    dev = FakeDevice(default="DISABLED")
    hardax.executeWithFallback(dev, script)
    assert dev.calls, "the command was never sent"
    assert dev.calls[0] == script, (
        "script was truncated before reaching the device:\n"
        f"  sent: {dev.calls[0]!r}\n  full: {script!r}")


def test_fallback_executor_still_handles_a_real_netstat_command():
    """The su / drop -p / swap-tool fallback must keep working for commands
    that genuinely start with a network tool."""
    dev = FakeDevice(default="tcp 0 0 0.0.0.0:23 LISTEN")
    out = hardax.executeWithFallback(dev, "netstat -tlnp 2>/dev/null | grep ':23'")
    assert dev.calls, "no candidate was attempted"
    assert any("netstat" in c for c in dev.calls)
    assert "LISTEN" in out
