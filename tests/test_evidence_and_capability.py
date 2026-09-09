"""Regression tests for the evidence, probe-failure and capability work.

Each test here exists because the behaviour it pins was observed to be wrong
against a real Android 13 device over SSH. The comment on each one records
what went wrong, so a future change that reintroduces the bug fails loudly
instead of quietly reporting a device secure.
"""

import pytest

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


# ── overlayfs mount-point awareness ──────────────────────────────────────────

import re
import subprocess
from conftest import load_all_checks


def _overlay_check(label):
    for c in load_all_checks():
        if c["label"] == label:
            return c
    raise AssertionError("check not found: " + label)


def _skip_without_posix_shell():
    """These helpers execute the check's real command against a real filesystem.

    On Windows `sh` can exist via Git Bash while path and permission semantics
    differ, so the commands run but produce meaningless results. Skip rather
    than assert on a platform the check was never written for.
    """
    import sys as _sys
    import shutil as _shutil
    if _sys.platform == "win32" or not _shutil.which("sh"):
        pytest.skip("needs a POSIX shell and filesystem semantics")


def _run_against(check, table, tmp_path):
    """Run a check's real command with /proc/mounts swapped for a fixture."""
    _skip_without_posix_shell()
    f = tmp_path / "mounts"
    f.write_text(table)
    cmd = check["command"].replace("cat /proc/mounts 2>/dev/null",
                                   "cat %s" % f)
    p = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    out = p.stdout.strip()
    return out, bool(re.search(check["safe_pattern"], out, re.M))


CONTAINER_TABLE = (
    "/dev/block/dm-15 /system_ext ext4 ro,seclabel 0 0\n"
    "/dev/block/dm-17 /vendor ext4 ro,seclabel 0 0\n"
    "overlay /data/rt/containers/a/overlay_rootfs overlay "
    "rw,lowerdir=/mnt/vendor/rt/containers/a/ro,"
    "upperdir=/data/rt/containers/a/overlay_rootfs,"
    "workdir=/data/rt/containers/a/work 0 0\n"
    "overlay /data/rt/containers/b/overlay_rootfs overlay rw,lowerdir=/x 0 0\n"
    "overlay /data/rt/containers/c/overlay_rootfs overlay rw,lowerdir=/x 0 0\n"
)

REMOUNT_TABLE = (
    "overlay /system overlay rw,lowerdir=/system,"
    "upperdir=/mnt/scratch/overlay/system/upper 0 0\n"
    "overlay /vendor overlay rw,lowerdir=/vendor 0 0\n"
    "/dev/block/by-name/userdata /mnt/scratch ext4 rw,seclabel 0 0\n"
)


def test_container_overlays_are_not_an_adb_remount(tmp_path):
    """Observed on an Android 13 device running containerised services: three
    overlay mounts under a container runtime's writable layer were
    reported CRITICAL as "adb remount active, dm-verity bypassed".

    The old command was `mount | grep -c '^overlay'`, which counts overlays
    anywhere and never looks at the mount point. Every firmware partition on
    that device was mounted ro and no overlay sat on one.
    """
    chk = _overlay_check("OverlayFS Active (adb remount)")
    out, safe = _run_against(chk, CONTAINER_TABLE, tmp_path)
    assert safe, out
    assert "firmware_overlays=0" in out
    assert "other_overlays=3" in out, "container overlays must still be counted"


def test_real_adb_remount_is_still_critical(tmp_path):
    """Narrowing the check must not blind it to the thing it exists to catch."""
    chk = _overlay_check("OverlayFS Active (adb remount)")
    out, safe = _run_against(chk, REMOUNT_TABLE, tmp_path)
    assert not safe, out
    assert "firmware_overlays=2" in out
    assert "/system" in out and "/vendor" in out, "must name the partitions"


def test_leftover_remount_scratch_is_caught(tmp_path):
    """A gap the bare count missed entirely: adb remount leaves /mnt/scratch
    behind. With no overlay currently mounted the old check scored count=0 and
    reported the device clean."""
    chk = _overlay_check("OverlayFS Active (adb remount)")
    table = ("/dev/block/by-name/userdata /mnt/scratch ext4 rw,seclabel 0 0\n"
             "/dev/block/dm-17 /vendor ext4 ro 0 0\n")
    out, safe = _run_against(chk, table, tmp_path)
    assert not safe, out
    assert "remount_scratch=[/mnt/scratch" in out


def test_toybox_on_type_mount_format_is_parsed(tmp_path):
    """`mount` prints "src on /mnt type fs (opts)" on some builds and
    "src /mnt fs opts" on others. Both must resolve to the same mount point."""
    chk = _overlay_check("OverlayFS Active (adb remount)")
    out, safe = _run_against(
        chk, "overlay on /vendor type overlay (rw,lowerdir=/vendor)\n", tmp_path)
    assert not safe, out
    assert "firmware_overlays=1" in out


def test_clean_device_reports_no_overlays(tmp_path):
    chk = _overlay_check("OverlayFS Active (adb remount)")
    out, safe = _run_against(chk, "/dev/block/dm-17 /vendor ext4 ro 0 0\n", tmp_path)
    assert safe, out
    assert "firmware_overlays=0 other_overlays=0" in out


def test_inventory_lists_where_each_overlay_sits(tmp_path):
    """The severity check reports counts; this one must preserve the paths so
    an analyst can confirm the classification instead of trusting it."""
    chk = _overlay_check("OverlayFS Mount Inventory")
    out, safe = _run_against(chk, CONTAINER_TABLE, tmp_path)
    assert safe, out
    assert out.count("overlay_at ") == 3
    assert "/data/rt/containers/a/overlay_rootfs" in out
    assert "count=3" in out


APEX_LOOP_TABLE = (
    "/dev/block/dm-17 /vendor ext4 ro,seclabel 0 0\n"
    "/dev/block/loop0 /apex/com.android.adbd@330000000 ext4 ro,seclabel 0 0\n"
    "/dev/block/loop1 /apex/com.android.art@330000000 ext4 ro,seclabel 0 0\n"
    "/dev/block/loop2 /apex/com.android.conscrypt@330000000 ext4 ro,seclabel 0 0\n"
)


def test_apex_loop_mounts_are_not_unexpected(tmp_path):
    """APEX Mainline modules are loop mounts on every Android 10+ device. The
    check's own description said "outside of APEX" but the command counted all
    of them, so widening its anchor would have fired on every modern device."""
    chk = _overlay_check("Unexpected Loop Device Mounts")
    out, safe = _run_against(chk, APEX_LOOP_TABLE, tmp_path)
    assert safe, out
    assert "apex_loop=3" in out, "APEX mounts must still be counted as evidence"


def test_side_loaded_loop_image_is_caught(tmp_path):
    """The original anchor was `^/dev/loop`, but Android names the source
    /dev/block/loopN, so the check matched nothing and reported every device
    clean regardless of what was loop-mounted."""
    chk = _overlay_check("Unexpected Loop Device Mounts")
    table = APEX_LOOP_TABLE + \
        "/dev/block/loop9 /data/local/tmp/rogue ext4 rw,seclabel 0 0\n"
    out, safe = _run_against(chk, table, tmp_path)
    assert not safe, out
    assert "non_apex_loop=1" in out
    assert "/data/local/tmp/rogue" in out, "must name the mount point"


def test_bare_dev_loop_source_is_still_matched(tmp_path):
    """Some builds report /dev/loopN rather than /dev/block/loopN."""
    chk = _overlay_check("Unexpected Loop Device Mounts")
    out, safe = _run_against(chk, "/dev/loop7 /mnt/hidden ext4 rw 0 0\n", tmp_path)
    assert not safe, out
    assert "/mnt/hidden" in out


# ── fstab encryption policy ──────────────────────────────────────────────────

def _run_fstab(tmp_path, files=None, dt_flags=None):
    """Run the fstab check with its search paths pointed at a fixture dir."""
    _skip_without_posix_shell()
    chk = _overlay_check("fstab Encryption Required")
    root = tmp_path / "etc"
    root.mkdir()
    for name, body in (files or {}).items():
        (root / name).write_text(body)
    dt = tmp_path / "dt_flags"
    if dt_flags is not None:
        dt.write_bytes(dt_flags.encode() + b"\x00")
    cmd = chk["command"]
    cmd = cmd.replace(
        "/vendor/etc/fstab.* /odm/etc/fstab.* /system/etc/fstab.* /etc/fstab* "
        "/first_stage_ramdisk/fstab.*", "%s/fstab.*" % root)
    cmd = cmd.replace(
        "/proc/device-tree/firmware/android/fstab/userdata/fsmgr_flags", str(dt))
    p = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    out = p.stdout.strip()
    return out, bool(re.search(chk["safe_pattern"], out, re.M))


FBE_LINE = ("/dev/block/by-name/userdata  /data  f2fs  noatime,nosuid,nodev  "
            "latemount,wait,formattable,fileencryption=aes-256-xts:aes-256-cts,"
            "metadata_encryption=aes-256-xts,quota\n")


def test_fbe_fstab_entry_is_safe(tmp_path):
    out, safe = _run_fstab(tmp_path, {"fstab.qcom": FBE_LINE})
    assert safe, out
    assert "data_encryption=fbe" in out and "metadata=yes" in out


def test_fstab_without_encryption_is_a_finding(tmp_path):
    line = ("/dev/block/by-name/userdata  /data  ext4  noatime,nosuid,nodev  "
            "wait,formattable,quota\n")
    out, safe = _run_fstab(tmp_path, {"fstab.qcom": line})
    assert not safe, out
    assert "data_encryption=none" in out


def test_unreadable_fstab_is_unmeasured_not_critical(tmp_path):
    """The old command was `[ -n "$D" ] && grep -c ...` with no else branch, so
    a device where no fstab is readable emitted nothing and, with
    empty_is_safe False, was reported CRITICAL "fstab must enforce encryption"
    without a single file having been read."""
    out, safe = _run_fstab(tmp_path)
    assert not safe, out
    assert hardax.isUnmeasured(out) == "UNMEASURED", out
    rows, _ = hardax.runChecks(
        FakeDevice(default=out), [_overlay_check("fstab Encryption Required")])
    assert rows[0]["status"] == "VERIFY", "must not assert a finding it never measured"


def test_device_tree_fstab_is_read(tmp_path):
    """Many SoCs carry the fstab in the kernel device tree rather than a file.
    The old check searched three path globs only and saw nothing on those
    devices, which landed in the same false CRITICAL."""
    out, safe = _run_fstab(
        tmp_path,
        dt_flags="wait,slotselect,avb,fileencryption=aes-256-xts:aes-256-cts,"
                 "metadata_encryption=aes-256-xts")
    assert safe, out
    assert "device-tree" in out


def test_encryptable_alone_does_not_satisfy_the_requirement(tmp_path):
    """encryptable= permits encryption, it does not require it, so it must not
    score the same as forceencrypt."""
    line = ("/dev/block/by-name/userdata  /data  ext4  noatime  "
            "wait,encryptable=footer\n")
    out, safe = _run_fstab(tmp_path, {"fstab.qcom": line})
    assert not safe, out
    assert "data_encryption=encryptable_only" in out


def test_commented_fstab_line_is_ignored(tmp_path):
    out, safe = _run_fstab(tmp_path, {"fstab.qcom": "# " + FBE_LINE})
    assert not safe, out
    assert hardax.isUnmeasured(out) == "UNMEASURED"


def test_legacy_fde_still_counts_as_encryption(tmp_path):
    line = ("/dev/block/bootdevice/by-name/userdata  /data  ext4  noatime  "
            "wait,forceencrypt=footer\n")
    out, safe = _run_fstab(tmp_path, {"fstab.qcom": line})
    assert safe, out
    assert "data_encryption=fde" in out


# ── summary counts must match the rows ───────────────────────────────────────

def test_summary_counts_match_the_row_statuses():
    """counts{} and the per-check statuses must not drift apart.

    The status and its counter were assigned independently in eight branches of
    runChecks. When the matched branch started reporting INFO for evidence
    collectors, the counter beneath it still incremented "safe", so a scan
    reported 367 SAFE while only 251 rows were actually SAFE. The summary line,
    the live dashboard and the analysis engine all read counts{}, so the whole
    report was wrong while every individual card was right.
    """
    import collections
    checks = [
        make_check(label="collector", safe_pattern=".", level="info"),
        make_check(label="real-pass", safe_pattern="^ok$", level="critical"),
        make_check(label="real-fail", safe_pattern="^never$", level="critical"),
        make_check(label="empty-safe", safe_pattern="^$", level="warning",
                   empty_is_safe=True, command="echo-nothing"),
    ]
    dev = FakeDevice(responses={"echo-nothing": ""}, default="ok")
    rows, counts = hardax.runChecks(dev, checks)
    actual = collections.Counter(r["status"].lower() for r in rows)
    for key, n in actual.items():
        assert counts.get(key, 0) == n, (
            "counts[%r]=%s but %d row(s) have that status: %s"
            % (key, counts.get(key), n,
               [(r["label"], r["status"]) for r in rows]))
    assert sum(counts.values()) == len(rows)


def test_evidence_collector_is_not_counted_as_a_pass():
    """A safe_pattern that matches any output is not a pass/fail rule."""
    dev = FakeDevice(default="anything at all")
    rows, counts = hardax.runChecks(
        dev, [make_check(label="c", safe_pattern=".", level="info")])
    assert rows[0]["status"] == "INFO"
    assert counts["safe"] == 0
