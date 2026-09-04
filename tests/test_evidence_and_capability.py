"""Regression tests for the evidence, probe-failure and capability work.

Each test here exists because the behaviour it pins was observed to be wrong
against a real Android 13 device over SSH. The comment on each one records
what went wrong, so a future change that reintroduces the bug fails loudly
instead of quietly reporting a device secure.
"""

import hardax
from conftest import FakeDevice, make_check


# ── stream separation ────────────────────────────────────────────────────────

def test_shell_result_keeps_streams_apart():
    """Both transports used to concatenate stdout and stderr and drop the exit
    code, leaving the engine to guess whether text was evidence or a failure."""
    r = hardax.ShellResult("data", "boom", 3)
    assert r.out == "data"
    assert r.err == "boom"
    assert r.code == 3
    assert r.merged == "data\nboom"


def test_shell_falls_back_to_merged_view():
    dev = FakeDevice(default="hello")
    assert dev.shell("anything") == "hello"


# ── probe failure detection ──────────────────────────────────────────────────

def test_binder_failure_on_stdout_is_a_probe_failure():
    """Observed on device: `cmd package list packages -3` prints
    "cmd: Failure calling service package: Failed transaction" to STDOUT with
    exit 2. It was being scored as evidence, and on checks with empty_is_safe
    it became SAFE."""
    res = hardax.ShellResult(
        "cmd: Failure calling service package: Failed transaction (2147483646)", "", 2)
    assert hardax.probeFailure(res)


def test_permission_denied_on_stderr_is_a_probe_failure():
    res = hardax.ShellResult("", "/proc/1/mem: Permission denied", 1)
    assert hardax.probeFailure(res)


def test_empty_output_is_not_a_probe_failure():
    """A command that ran and found nothing is a real result, not a failure.
    Conflating the two is what made 240 checks able to pass without evidence."""
    assert not hardax.probeFailure(hardax.ShellResult("", "", 0))


def test_real_findings_mentioning_an_error_word_are_not_discarded():
    """A check grepping a log for "Permission denied" must keep its findings.
    probeFailure only fires when EVERY line looks like a device failure."""
    res = hardax.ShellResult(
        "avc: denied { read } for comm=app\n"
        "Permission denied\n"
        "10 more violations follow", "", 0)
    assert not hardax.probeFailure(res)


def test_long_denial_list_is_evidence_not_failure():
    """Bounded to a few lines so a genuine list of denied paths survives."""
    res = hardax.ShellResult("\n".join(["Permission denied"] * 12), "", 1)
    assert not hardax.probeFailure(res)


# ── stdout-only scoring ──────────────────────────────────────────────────────

def test_stderr_cannot_satisfy_a_safe_pattern():
    """stderr used to be merged into the matched text, so a failure message
    could satisfy a safe_pattern and score the device as secure."""
    dev = FakeDevice()
    dev.shellEx = lambda cmd: hardax.ShellResult("", "Enforcing", 0)
    rows, _ = hardax.runChecks(
        dev, [make_check(label="selinux", safe_pattern="Enforcing", level="critical")])
    assert rows[0]["status"] != "SAFE"


def test_probe_failure_never_reaches_empty_is_safe():
    """The exact shape of the bug: a failed probe on a check with
    empty_is_safe was reported SAFE."""
    dev = FakeDevice()
    dev.shellEx = lambda cmd: hardax.ShellResult(
        "cmd: Failure calling service settings: Failed transaction", "", 2)
    rows, _ = hardax.runChecks(dev, [make_check(
        label="s", safe_pattern="^$", empty_is_safe=True, level="critical")])
    assert rows[0]["status"] == "VERIFY"
    assert "probe failed" in rows[0]["evidence"]["basis"]


# ── unmeasured declarations ──────────────────────────────────────────────────

def test_unmeasured_token_routes_to_verify_not_a_finding():
    """A check that cannot measure a property must not assert a bad state.
    Four critical checks were printing "Disabled"/"NotEnforced" when their
    probe failed, reporting the device insecure on evidence never collected."""
    for token in ("UNMEASURED", "NOT_OBSERVABLE", "NOT_DETERMINED", "NOT_APPLICABLE"):
        dev = FakeDevice()
        dev.shellEx = lambda cmd, t=token: hardax.ShellResult(t, "", 0)
        rows, _ = hardax.runChecks(dev, [make_check(
            label="k", safe_pattern="^Enabled$", level="critical")])
        assert rows[0]["status"] == "VERIFY", token


def test_unmeasured_token_does_not_hijack_real_output():
    dev = FakeDevice()
    dev.shellEx = lambda cmd: hardax.ShellResult("UNMEASURED_BY_DESIGN=1", "", 0)
    assert not hardax.isUnmeasured("UNMEASURED_BY_DESIGN=1")


# ── evidence record ──────────────────────────────────────────────────────────

def test_every_row_carries_an_evidence_record():
    dev = FakeDevice(default="value")
    rows, _ = hardax.runChecks(dev, [make_check(safe_pattern="value")])
    ev = rows[0]["evidence"]
    assert ev["stdout"] == "value"
    assert ev["exit_code"] == 0
    assert "matched safe_pattern" in ev["basis"]


# ── transport capability gate ────────────────────────────────────────────────

def test_binder_dependent_commands_are_recognised():
    for cmd in ("dumpsys battery", "pm list packages", "settings get global x",
                "cmd package list", "appops get pkg OP",
                "getprop x; dumpsys wifi", "service list"):
        assert hardax.commandNeedsBinder(cmd), cmd


def test_non_binder_commands_are_not_gated():
    """These must keep running on a transport without framework access."""
    for cmd in ("getprop ro.build.version.sdk", "cat /proc/cmdline",
                "ls -la /dev/mem", "mount | grep ' /data '",
                "grep -c nosuid /proc/mounts"):
        assert not hardax.commandNeedsBinder(cmd), cmd


def test_found_zero_services_counts_as_no_binder():
    """Observed on device: a vendor SELinux domain answers `service list` with
    "Found 0 services:", which is as unusable as no answer at all."""
    dev = FakeDevice(responses={"service list": "Found 0 services:"}, default="")
    assert probe_binder(dev) is False


def test_populated_service_list_counts_as_binder():
    dev = FakeDevice(responses={"service list": "Found 210 services:\n0 activity"},
                     default="")
    assert probe_binder(dev) is True


def probe_binder(dev):
    return hardax.probeCapabilities(dev)["binder"]


def test_gated_check_is_skipped_and_says_why():
    dev = FakeDevice(default="")
    rows, counts = hardax.runChecks(
        dev, [make_check(label="bt", command="dumpsys bluetooth_manager | grep x",
                         level="critical")],
        capabilities={"binder": False})
    assert rows[0]["status"] == "SKIPPED"
    assert "NOT APPLICABLE" in rows[0]["result"]
    assert dev.calls == [], "a gated check must not be executed"


def test_gate_is_inactive_when_binder_is_available():
    dev = FakeDevice(default="ok")
    rows, _ = hardax.runChecks(
        dev, [make_check(command="dumpsys x", safe_pattern="ok")],
        capabilities={"binder": True})
    assert rows[0]["status"] == "SAFE"


# ── pipeline emulation ───────────────────────────────────────────────────────

def test_quoted_pipe_does_not_split_a_filter_stage():
    """applyFilters used a naive split("|"), which tore
    `grep -vE '127.0.0.1|::1|localhost'` into four stages. The grep stage was
    left with an unterminated quote, matched nothing, and being inverted kept
    every line, so loopback traffic was reported as an external connection."""
    cmd = ("netstat -tunp | grep ESTABLISHED | grep -vE '127.0.0.1|::1|localhost' "
           "| head -20 || ss -tunp | grep ESTAB | head -20")
    stages = hardax.splitUnquotedPipes(hardax.splitUnquotedPipes(cmd, limit=1)[1])
    assert [s.strip() for s in stages] == [
        "grep ESTABLISHED",
        "grep -vE '127.0.0.1|::1|localhost'",
        "head -20",
    ]


def test_loopback_is_actually_filtered_out():
    out = ("tcp 0 0 127.0.0.1:6379 127.0.0.1:26404 ESTABLISHED 4789/redis\n"
           "tcp 0 0 192.0.2.10:22 192.0.2.44:51234 ESTABLISHED 9001/sshd\n"
           "tcp 0 0 127.0.0.1:26270 127.0.0.1:6379 ESTABLISHED 4457/app")
    cmd = "netstat -tunp | grep ESTABLISHED | grep -vE '127.0.0.1|::1|localhost' | head -20"
    result = hardax.applyFilters(out, cmd)
    assert "127.0.0.1" not in result
    assert "192.0.2.10" in result


def test_double_pipe_branch_is_not_treated_as_a_filter():
    cmd = "netstat -lntp | grep LISTEN || ss -lntp | grep -v ESTAB"
    stages = hardax.splitUnquotedPipes(hardax.splitUnquotedPipes(cmd, limit=1)[1])
    assert [s.strip() for s in stages] == ["grep LISTEN"]


def test_unmeasured_token_may_carry_detail():
    """A declaration must be able to say how far the probe got. The dalvik-cache
    check reports `UNMEASURED dirs_checked_clean enumeration_denied=82`, which
    tells the reader the directory modes WERE verified and only the file walk
    was blocked. Requiring the token to stand alone would throw that away."""
    assert hardax.isUnmeasured("UNMEASURED dirs_checked_clean enumeration_denied=82") == "UNMEASURED"
    assert hardax.isUnmeasured("NOT_OBSERVABLE /proc/config.gz absent") == "NOT_OBSERVABLE"
    assert hardax.isUnmeasured("UNMEASURED") == "UNMEASURED"
    # a value that merely starts with similar text is not a declaration
    assert hardax.isUnmeasured("UNMEASUREDX foo") == ""
    assert hardax.isUnmeasured("count=UNMEASURED") == ""


def test_binder_optional_checks_still_run_without_binder():
    """A check that carries a non-binder fallback must not be gated away.

    Several package and policy checks can answer from /data/system/packages.xml
    or device_policies.xml when the framework is unreachable. Gating them on the
    mere presence of `pm` in the command would discard a working probe.
    """
    dev = FakeDevice(default="ok")
    chk = make_check(command="pm list packages | grep x", safe_pattern="ok")
    chk["binder_optional"] = True
    rows, _ = hardax.runChecks(dev, [chk], capabilities={"binder": False})
    assert rows[0]["status"] == "SAFE"
    assert dev.calls, "a binder_optional check must still be executed"


def test_binder_required_checks_are_still_gated():
    dev = FakeDevice(default="ok")
    rows, _ = hardax.runChecks(
        dev, [make_check(command="pm list packages | grep x")],
        capabilities={"binder": False})
    assert rows[0]["status"] == "SKIPPED"
    assert dev.calls == []
