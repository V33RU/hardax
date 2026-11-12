"""Regression tests for the evidence, probe-failure and capability work.

Each test here exists because the behaviour it pins was observed to be wrong
against a real Android 13 device over SSH. The comment on each one records
what went wrong, so a future change that reintroduces the bug fails loudly
instead of quietly reporting a device secure.
"""

import os
import shutil

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


# ── renamed su binaries ──────────────────────────────────────────────────────

SU_CHECK = "Renamed su Binary (su variants) and Their Permissions"


def _run_su_check(tmp_path, planted, denied=False):
    """Run the su-variant check against a fixture tree of executable dirs.

    planted maps a directory name to {filename: octal mode}.
    """
    _skip_without_posix_shell()
    import os
    chk = _overlay_check(SU_CHECK)
    dirs = []
    for d, files in planted.items():
        p = tmp_path / d
        p.mkdir()
        for name, mode in files.items():
            f = p / name
            f.write_text("")
            os.chmod(str(f), mode)
        dirs.append(str(p))
    unreadable = None
    if denied:
        unreadable = tmp_path / "denied"
        unreadable.mkdir()
        os.chmod(str(unreadable), 0o000)
        dirs.append(str(unreadable))
    cmd = chk["command"]
    real = cmd[cmd.index("for d in ") + 9: cmd.index("; do")]
    try:
        out = subprocess.run(["sh", "-c", cmd.replace(real, " ".join(dirs))],
                             capture_output=True, text=True).stdout.strip()
    finally:
        # restore the mode or pytest cannot remove its own tmp_path afterwards
        if unreadable is not None:
            os.chmod(str(unreadable), 0o755)
    return out, bool(re.search(chk["safe_pattern"], out, re.M))


def test_renamed_su_binary_is_detected_with_its_mode(tmp_path):
    """A root helper does not have to be called su. Checking only
    /system/bin/su and /system/xbin/su misses suX, su1, .su, daemonsu and the
    rest, which is the entire point of renaming it."""
    out, safe = _run_su_check(tmp_path, {
        "xbin": {"suX": 0o4755},
        "vendorbin": {"daemonsu": 0o6755},
        "datalocal": {"su1": 0o755},
    })
    assert not safe, out
    assert "su_variants=3" in out
    assert "setuid=2" in out, "setuid bit must be counted separately from presence"
    assert "suX=-rwsr-xr-x" in out, "mode must be reported alongside the path"


def test_binaries_merely_starting_with_su_are_not_flagged(tmp_path):
    """surfaceflinger, sulogin and suspend all begin with su and are legitimate.
    An over-broad pattern here would fire on every Android device."""
    out, safe = _run_su_check(tmp_path, {
        "bin": {"surfaceflinger": 0o755, "sulogin": 0o755,
                "suspend": 0o755, "sh": 0o755},
    })
    assert safe, out
    assert "su_variants=0" in out


def test_denied_directory_is_counted_not_treated_as_empty(tmp_path):
    out, safe = _run_su_check(tmp_path, {"xbin": {"suX": 0o4755}}, denied=True)
    assert not safe, out
    assert "denied_dirs=1" in out


def test_no_listable_directory_reports_unmeasured(tmp_path):
    out, safe = _run_su_check(tmp_path, {}, denied=True)
    assert hardax.isUnmeasured(out) == "UNMEASURED", out
    rows, _ = hardax.runChecks(FakeDevice(default=out), [_overlay_check(SU_CHECK)])
    assert rows[0]["status"] == "VERIFY"


def test_world_writable_su_variant_is_counted(tmp_path):
    out, _ = _run_su_check(tmp_path, {"xbin": {"su": 0o777}})
    assert "group_or_world_writable=1" in out, out


# ── unnecessary-binary detection (PCI-DSS 2.2.4 / NIST CM-7) ─────────────────

def _run_scan_check(label, tmp_path, planted, denied=False):
    """Run a path-scanning presence check against a fixture of executable dirs."""
    _skip_without_posix_shell()
    import os
    chk = _overlay_check(label)
    dirs = []
    if planted:
        d = tmp_path / "bin"
        d.mkdir()
        for name, mode in planted.items():
            f = d / name
            f.write_text("")
            os.chmod(str(f), mode)
        dirs.append(str(d))
    blocked = None
    if denied:
        blocked = tmp_path / "blocked"
        blocked.mkdir()
        os.chmod(str(blocked), 0o000)
        dirs.append(str(blocked))
    cmd = chk["command"]
    real = cmd[cmd.index("for d in ") + 9: cmd.index("; do")]
    try:
        out = subprocess.run(["sh", "-c", cmd.replace(real, " ".join(dirs))],
                             capture_output=True, text=True).stdout.strip()
    finally:
        if blocked is not None:
            os.chmod(str(blocked), 0o755)
    return out, bool(re.search(chk["safe_pattern"], out, re.M))


def test_factory_and_ftm_binaries_are_detected(tmp_path):
    """A Bluetooth FTM tool takes raw HCI opcodes and drives the controller
    directly, bypassing the framework entirely. Nothing else in the suite looks
    for this class of binary."""
    out, safe = _run_scan_check(
        "Factory, FTM and Diagnostic Test Binaries Present", tmp_path,
        {"bt_ftm_test": 0o755, "qttestservice": 0o755, "diag_mdlog": 0o755,
         "surfaceflinger": 0o755, "sh": 0o755})
    assert not safe, out
    assert "factory_test_binaries=3" in out
    assert "surfaceflinger" not in out


def test_dormant_offensive_binaries_are_detected(tmp_path):
    """Process and port checks only see these once they run. A staged
    frida-server or netcat sitting on disk is the pre-stage."""
    out, safe = _run_scan_check(
        "Network and Exfiltration Binaries Present on Disk", tmp_path,
        {"nc": 0o755, "socat": 0o755, "frida-server": 0o700, "logcat": 0o755})
    assert not safe, out
    assert "offensive_net_binaries=3" in out


def test_simpleperf_is_not_flagged_as_a_debugger(tmp_path):
    """simpleperf ships in AOSP; flagging it would fire on every device."""
    out, safe = _run_scan_check("System Debug Binaries", tmp_path,
                                {"simpleperf": 0o755, "sh": 0o755})
    assert safe, out
    assert "debug_binaries=0" in out


def test_debug_binaries_search_is_no_longer_two_fixed_paths(tmp_path):
    out, safe = _run_scan_check("System Debug Binaries", tmp_path,
                                {"gdbserver": 0o755, "ltrace": 0o755})
    assert not safe, out
    assert "debug_binaries=2" in out
    assert "=-rwx" in out, "mode must be reported per hit"


def test_nothing_found_but_directories_denied_is_not_clean(tmp_path):
    """The defect this whole class keeps reproducing: an empty result from a
    walk that could not read anything is not a pass."""
    out, safe = _run_scan_check(
        "Network and Exfiltration Binaries Present on Disk", tmp_path,
        {"sh": 0o755}, denied=True)
    assert not safe, out
    assert hardax.isUnmeasured(out) == "UNMEASURED", out


def test_suid_binary_is_now_a_finding_not_an_inventory(tmp_path):
    """AOSP ships zero setuid binaries. This was info level with safe_pattern
    '.', so it printed a list and could never raise a finding."""
    import os
    _skip_without_posix_shell()
    chk = _overlay_check("SUID Binaries")
    d = tmp_path / "sys"
    d.mkdir()
    for name, mode in (("plain", 0o755), ("suidbin", 0o4755)):
        f = d / name
        f.write_text("")
        os.chmod(str(f), mode)
    cmd = chk["command"].replace("/system /vendor /product /odm /apex /data", str(d))
    out = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True).stdout.strip()
    assert chk["level"] in ("high", "critical"), "must be failable, not info"
    assert not re.search(chk["safe_pattern"], out, re.M), out
    assert "suid_binaries=1" in out


# ── network security configuration inside installed APKs ────────────────────

def _fake_axml(names):
    """A compiled-AXML-shaped blob: element and attribute names as UTF-16LE.

    Real AXML keeps names in a UTF-16 string pool, which is why a plain
    `grep -a` finds nothing and `tr -d '\\0' | grep` finds them. Boolean
    attribute values are typed integers and never appear as strings, which is
    the hard limit on what a device shell can determine.
    """
    out = b"\x03\x00\x08\x00"
    for n in names:
        out += n.encode("utf-16-le") + b"\x00\x00"
    return out


def _apk(path, xml_files):
    import zipfile
    with zipfile.ZipFile(str(path), "w") as z:
        for name, names in xml_files.items():
            z.writestr("res/xml/" + name, _fake_axml(names))


def _run_apk_check(label, tmp_path, apks):
    _skip_without_posix_shell()
    import shutil
    if not shutil.which("unzip"):
        pytest.skip("unzip not available on this host")
    chk = _overlay_check(label)
    root = tmp_path / "app"
    root.mkdir()
    for pkg, xmls in apks.items():
        d = root / pkg
        d.mkdir()
        _apk(d / "base.apk", xmls)
    cmd = chk["command"].replace(
        "/data/app/*/*/base.apk /data/app/*/base.apk",
        "%s/*/base.apk" % root).replace("ls /data/app ", "ls %s " % root)
    out = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True).stdout.strip()
    return out, bool(re.search(chk["safe_pattern"], out, re.M))


NSC_DEBUG = {"nsc.xml": ["network-security-config", "base-config",
                         "trust-anchors", "debug-overrides", "certificates"]}
NSC_PINS = {"nsc.xml": ["network-security-config", "domain-config", "domain",
                        "trust-anchors", "overridePins", "pin-set"]}
NSC_CLEAN = {"nsc.xml": ["network-security-config", "base-config",
                         "trust-anchors", "certificates", "system"]}


def test_debug_overrides_in_a_shipping_apk_is_detected(tmp_path):
    out, safe = _run_apk_check(
        "Installed APK Ships debug-overrides in Its Network Security Config",
        tmp_path, {"com.a": NSC_DEBUG, "com.b": NSC_CLEAN})
    assert not safe, out
    assert "apks_with_debug_overrides=1" in out


def test_override_pins_declaration_is_detected(tmp_path):
    out, safe = _run_apk_check(
        "Installed APK Declares overridePins in Its Network Security Config",
        tmp_path, {"com.a": NSC_PINS, "com.b": NSC_CLEAN})
    assert not safe, out
    assert "apks_with_override_pins=1" in out


@pytest.mark.parametrize("label", [
    "Installed APK Ships debug-overrides in Its Network Security Config",
    "Installed APK Declares overridePins in Its Network Security Config",
])
def test_clean_configs_do_not_fire(label, tmp_path):
    out, safe = _run_apk_check(label, tmp_path, {"com.b": NSC_CLEAN})
    assert safe, (label, out)


def test_nsc_inventory_counts_apps_with_a_config(tmp_path):
    out, safe = _run_apk_check(
        "Installed APKs Shipping a Network Security Configuration",
        tmp_path, {"com.a": NSC_DEBUG, "com.b": NSC_CLEAN, "com.c": NSC_PINS})
    assert "apks_with_nsc=3" in out, out


def test_dead_network_security_config_find_is_gone():
    """The old command searched the filesystem for network_security_config.xml.
    That file is compiled into the APK under res/xml and never exists on disk,
    so it returned empty on every device ever scanned."""
    chk = _overlay_check("Network Security Config Files (sample)")
    assert "-name 'network_security_config.xml'" not in chk["command"]
    assert "unzip_available" in chk["command"]


# ── verified boot signing key ────────────────────────────────────────────────

AVB_PATH_GLOB = ("for p in /dev/block/by-name/vbmeta$S "
                 "/dev/block/bootdevice/by-name/vbmeta$S "
                 "/dev/block/by-name/vbmeta /dev/block/bootdevice/by-name/vbmeta "
                 "/dev/block/platform/*/by-name/vbmeta$S "
                 "/dev/block/platform/*/by-name/vbmeta; do")


def _avb_image(path, algorithm_type, signature_size, key_bits=None):
    """A vbmeta image with a real AVB public key blob in its aux block.

    The zeros matter: `od` collapses repeated identical lines to "*" unless
    -v is passed, which silently truncated the hex dump and made the parse
    return nothing. A real vbmeta.img happened to have varied bytes and hid it.

    Layout verified against a real vbmeta.img. Header: magic "AVB0" at 0,
    authentication_data_block_size u64 at 12, auxiliary_data_block_size u64 at
    20, algorithm_type u32 at 28, signature_offset/size u64 at 48/56,
    public_key_offset/size u64 at 64/72. The aux block holds the public key,
    an AvbRSAPublicKeyHeader whose key_num_bits is a big-endian u32 at its
    offset 0, followed by the modulus and rr.

    key_bits defaults to signature_size * 8, which is the relationship RSA
    guarantees. Passing it explicitly builds an image whose key and signature
    length disagree, which is what the MISMATCH branch exists to catch.
    """
    import struct
    if key_bits is None:
        key_bits = signature_size * 8
    if signature_size:
        pk = (struct.pack(">II", key_bits, 0x12345678)
              + b"\x11" * (key_bits // 8) + b"\x22" * (key_bits // 8))
    else:
        pk = b""                                  # unsigned: no key at all
    auth = 32 + signature_size                    # hash then signature
    b = bytearray(256)
    b[0:4] = b"AVB0"
    struct.pack_into(">II", b, 4, 1, 0)           # required libavb 1.0
    struct.pack_into(">Q", b, 12, auth)
    struct.pack_into(">Q", b, 20, len(pk))
    struct.pack_into(">I", b, 28, algorithm_type)
    struct.pack_into(">QQ", b, 48, 32, signature_size)
    struct.pack_into(">QQ", b, 64, 0, len(pk))
    b[176:189] = b"avbtool 1.1.0"
    path.write_bytes(bytes(b) + b"\x00" * auth + pk + b"\x00" * 2048)
    return str(path)


def _run_avb(label, tmp_path, img=None, raw=None):
    _skip_without_posix_shell()
    chk = _overlay_check(label)
    if raw is not None:
        p = tmp_path / "vbmeta.img"
        p.write_bytes(raw)
        img = str(p)
    cmd = chk["command"].replace(AVB_PATH_GLOB, "for p in %s; do" % (img or "/nonexistent"))
    out = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True).stdout.strip()
    return out, bool(re.search(chk["safe_pattern"], out, re.M))


SIGNED_CHECK = "vbmeta Is Cryptographically Signed"
KEY_CHECK = "Verified Boot Signing Key Strength"


def test_unsigned_vbmeta_is_detected(tmp_path):
    """AVB permits algorithm_type NONE: a vbmeta with no signature at all.
    The bootloader still reports a verified boot state and the device still
    looks locked, so no property-based check sees this."""
    img = _avb_image(tmp_path / "u.img", 0, 0)
    out, safe = _run_avb(SIGNED_CHECK, tmp_path, img)
    assert not safe, out
    assert "vbmeta_signed=no" in out


def test_signed_vbmeta_passes(tmp_path):
    img = _avb_image(tmp_path / "s.img", 2, 512)      # SHA256_RSA4096
    out, safe = _run_avb(SIGNED_CHECK, tmp_path, img)
    assert safe, out
    assert "alg=SHA256_RSA4096" in out and "key_bits=4096" in out


def test_rsa2048_signing_key_is_flagged(tmp_path):
    img = _avb_image(tmp_path / "w.img", 1, 256)      # SHA256_RSA2048
    out, safe = _run_avb(KEY_CHECK, tmp_path, img)
    assert not safe, out
    assert "avb_key=WEAK" in out and "key_bits=2048" in out


def test_rsa4096_and_rsa8192_pass(tmp_path):
    for n, (alg, sz, bits) in enumerate([(2, 512, 4096), (3, 1024, 8192), (5, 512, 4096)]):
        img = _avb_image(tmp_path / ("ok%d.img" % n), alg, sz)
        out, safe = _run_avb(KEY_CHECK, tmp_path, img)
        assert safe, out
        assert "key_bits=%d" % bits in out


def test_key_strength_defers_to_the_signing_check_when_unsigned(tmp_path):
    """One defect must not produce two findings. An unsigned image is the
    signing check's to report, so the strength check stands down."""
    img = _avb_image(tmp_path / "u.img", 0, 0)
    out, _ = _run_avb(KEY_CHECK, tmp_path, img)
    assert hardax.isUnmeasured(out) == "NOT_APPLICABLE", out
    rows, _ = hardax.runChecks(FakeDevice(default=out), [_overlay_check(KEY_CHECK)])
    assert rows[0]["status"] == "VERIFY"


def test_non_avb_or_unreadable_partition_is_unmeasured(tmp_path):
    out, safe = _run_avb(SIGNED_CHECK, tmp_path, raw=b"\x00" * 80)
    assert not safe
    assert hardax.isUnmeasured(out) == "UNMEASURED", out
    out, safe = _run_avb(SIGNED_CHECK, tmp_path, img="/nonexistent/vbmeta")
    assert hardax.isUnmeasured(out) == "UNMEASURED", out


# --------------------------------------------------------------------------
# Verified boot hash tree digest algorithm (BOOT-VERITYHASH-001)
# --------------------------------------------------------------------------

VERITY_HASH_CHECK = "Verified Boot Hash Tree Digest Algorithm"


def _hashtree_descriptor(algo, partition):
    """One AvbHashtreeDescriptor, big-endian, per libavb.

    Field order: tag u64=1, num_bytes_following u64, dm_verity_version u32,
    image_size u64, tree_offset u64, tree_size u64, data_block_size u32,
    hash_block_size u32, fec_num_roots u32, fec_offset u64, fec_size u64,
    hash_algorithm[32] at offset 88, then the name and digest lengths.

    hash_algorithm is a null-padded ASCII string, which is the only reason a
    device shell can recover it at all: nothing here is ASN.1.
    """
    import struct
    d = bytearray(176)
    struct.pack_into(">QQ", d, 0, 1, 168)
    struct.pack_into(">I", d, 16, 1)
    d[88:88 + len(algo)] = algo.encode()
    struct.pack_into(">III", d, 120, len(partition), 32, 32)
    return bytes(d) + partition.encode() + b"\x00" * 64


def _vbmeta_with_descriptors(path, descriptors):
    """A vbmeta image whose aux block holds the given descriptors.

    The trailing zeros are deliberate: a real vbmeta partition is mostly empty
    after the aux block, and the hash algorithm has to survive being read out
    of that.
    """
    import struct
    aux = b"".join(descriptors) + b"\xde\xad" * 256
    h = bytearray(256)
    h[0:4] = b"AVB0"
    struct.pack_into(">II", h, 4, 1, 0)
    struct.pack_into(">Q", h, 20, len(aux))
    struct.pack_into(">I", h, 28, 2)
    struct.pack_into(">QQ", h, 128, 0, sum(len(d) for d in descriptors))
    h[176:189] = b"avbtool 1.1.0"
    path.write_bytes(bytes(h) + aux + b"\x00" * 4096)
    return path


def _run_verity_hash(tmp_path, image=None):
    """Run the real command with /dev/block rerooted under tmp_path."""
    _skip_without_posix_shell()
    chk = _overlay_check(VERITY_HASH_CHECK)
    root = tmp_path / "root"
    (root / "dev" / "block" / "by-name").mkdir(parents=True, exist_ok=True)
    if image is not None:
        shutil.copyfile(str(image), str(root / "dev" / "block" / "by-name" / "vbmeta"))
    cmd = chk["command"].replace("/dev/block/", str(root) + "/dev/block/")
    out = subprocess.run(["sh", "-c", cmd], capture_output=True, text=True).stdout.strip()
    return out, bool(re.search(chk["safe_pattern"], out, re.M))


def test_sha256_hashtree_reads_clean(tmp_path):
    img = _vbmeta_with_descriptors(tmp_path / "ok.img", [
        _hashtree_descriptor("sha256", "system"),
        _hashtree_descriptor("sha256", "vendor"),
    ])
    out, safe = _run_verity_hash(tmp_path, img)
    assert safe, out
    assert "algs=sha256" in out, out


def test_sha1_hashtree_is_detected(tmp_path):
    """dm-verity is on and every other verity check passes; the digest is
    still SHA-1. One weak partition among strong ones has to surface."""
    img = _vbmeta_with_descriptors(tmp_path / "weak.img", [
        _hashtree_descriptor("sha1", "system"),
        _hashtree_descriptor("sha256", "vendor"),
    ])
    out, safe = _run_verity_hash(tmp_path, img)
    assert not safe, out
    assert out.startswith("verity_hash=WEAK"), out
    assert "sha1" in out and "sha256" in out, out


def test_vbmeta_with_no_hash_descriptors_is_unmeasured(tmp_path):
    """A top-level vbmeta holding only chain descriptors names no algorithm of
    its own. That is an unanswered question, not a clean result."""
    img = _vbmeta_with_descriptors(tmp_path / "chain.img", [])
    out, safe = _run_verity_hash(tmp_path, img)
    assert not safe, out
    assert hardax.isUnmeasured(out) == "UNMEASURED", out
    assert "vbmeta_images=1" in out, out


def test_no_readable_vbmeta_is_unmeasured_not_clean(tmp_path):
    """The whole defect class this suite guards against: a probe that reads
    nothing must not report the device as safe."""
    out, safe = _run_verity_hash(tmp_path, None)
    assert not safe, out
    assert hardax.isUnmeasured(out) == "UNMEASURED", out


def test_non_avb_partition_does_not_count_as_an_image(tmp_path):
    """The AVB0 magic gates every byte read after it, so a partition that is
    readable but is not an AVB image cannot contribute a stray token."""
    p = tmp_path / "junk.img"
    p.write_bytes(b"sha1" + b"\x00" * 4096)
    out, safe = _run_verity_hash(tmp_path, p)
    assert not safe, out
    assert hardax.isUnmeasured(out) == "UNMEASURED", out
    assert "no readable vbmeta" in out, out


# --------------------------------------------------------------------------
# Userdata contents encryption cipher (STOR-FBECIPHER-001)
#
# Scope is contents_mode only. The first version of this check also scored
# filenames_mode, which "Userdata Filenames Encryption Cipher" already scores, so an
# Adiantum device produced two findings for one condition and an hctr2 device
# got two checks disagreeing. test_contents_and_filenames_are_scored_once
# pins the split.
# --------------------------------------------------------------------------

FBE_CIPHER_CHECK = "Userdata Contents Encryption Cipher"


def _run_fbe(tmp_path, props=None):
    """Run the real command with getprop stubbed to the given properties.

    props=None stands in for a shell where getprop is denied or absent.
    """
    _skip_without_posix_shell()
    chk = _overlay_check(FBE_CIPHER_CHECK)
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    if props is None:
        # getprop present but answering nothing and failing, which is what a
        # denied or non-Android shell looks like. Stubbed rather than left to
        # the host's PATH so the result does not depend on the test machine.
        lines = ['#!/bin/sh', 'exit 1', '']
    else:
        lines = ['#!/bin/sh', 'case "$1" in']
        for k, v in props.items():
            lines.append('%s) echo "%s";;' % (k, v))
        lines += ['*) echo "";;', 'esac', '']
    stub = bindir / "getprop"
    stub.write_text("\n".join(lines))
    stub.chmod(0o755)
    # Prepend, never replace: replacing PATH loses `sh` itself.
    env = dict(os.environ, PATH=str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    out = subprocess.run(["sh", "-c", chk["command"]], capture_output=True,
                         text=True, env=env).stdout.strip()
    return out, bool(re.search(chk["safe_pattern"], out, re.M))


def test_unset_cipher_properties_report_the_aosp_default(tmp_path):
    """Unset does not mean unknown here: vold falls back to aes-256-xts. The
    output has to say the verdict rests on a default, not a measurement."""
    out, safe = _run_fbe(tmp_path, {"ro.crypto.type": "file",
                                    "ro.build.version.sdk": "34"})
    assert safe, out
    assert "aosp-default" in out, out


def test_explicit_strong_cipher_reads_clean(tmp_path):
    out, safe = _run_fbe(tmp_path, {
        "ro.crypto.type": "file",
        "ro.crypto.volume.contents_mode": "aes-256-xts",
        "ro.crypto.volume.filenames_mode": "aes-256-cts",
        "ro.build.version.sdk": "34"})
    assert safe, out
    assert "aosp-default" not in out, out


def test_filenames_mode_never_changes_this_verdict(tmp_path):
    """filenames_mode is context here, not a scored field. aes-256-hctr2 is a
    valid modern mode; this check must not score it either way, or the two
    could disagree on the same device."""
    for fm in ("aes-256-cts", "aes-256-hctr2", "adiantum", "something-odd"):
        out, safe = _run_fbe(tmp_path, {
            "ro.crypto.type": "file",
            "ro.crypto.volume.contents_mode": "aes-256-xts",
            "ro.crypto.volume.filenames_mode": fm,
            "ro.build.version.sdk": "34"})
        assert safe, (fm, out)
        assert "filenames_mode_context=%s" % fm in out, out


def test_weak_contents_cipher_is_caught(tmp_path):
    """The device reports state=encrypted and type=file and every other
    storage check passes. Only the contents mode shows the weakness."""
    out, safe = _run_fbe(tmp_path, {
        "ro.crypto.type": "file",
        "ro.crypto.volume.contents_mode": "aes-128-cbc",
        "ro.build.version.sdk": "34"})
    assert not safe, out
    assert out.startswith("fbe_contents=UNEXPECTED"), out


def test_adiantum_is_named_in_evidence_but_is_not_a_finding(tmp_path):
    """Adiantum is sanctioned where the SoC has no AES acceleration. It is a
    tradeoff to record, not a misconfiguration, so it gets its own token in
    the evidence and does not become a finding. It must not become one here
    either, because Adiantum sets both modes and the filenames check already
    reports it, which is how this check first produced a duplicate."""
    out, safe = _run_fbe(tmp_path, {
        "ro.crypto.type": "file",
        "ro.crypto.volume.contents_mode": "adiantum",
        "ro.crypto.volume.filenames_mode": "adiantum",
        "ro.build.version.sdk": "34"})
    assert safe, out
    assert out.startswith("fbe_contents=ADIANTUM"), out
    assert "contents_mode=adiantum" in out, out


def test_full_disk_encryption_is_not_applicable(tmp_path):
    """FDE has no per-volume cipher. Reporting a finding here would double up
    with the encryption-type check on the same legacy device."""
    out, safe = _run_fbe(tmp_path, {"ro.crypto.type": "block",
                                    "ro.build.version.sdk": "28"})
    assert not safe, out
    assert hardax.isUnmeasured(out) == "NOT_APPLICABLE", out


def test_getprop_that_does_not_answer_is_unmeasured(tmp_path):
    out, safe = _run_fbe(tmp_path, None)
    assert not safe, out
    assert hardax.isUnmeasured(out) == "UNMEASURED", out


def test_crypto_type_unset_is_unmeasured(tmp_path):
    out, safe = _run_fbe(tmp_path, {"ro.build.version.sdk": "34"})
    assert not safe, out
    assert hardax.isUnmeasured(out) == "UNMEASURED", out


def test_each_cipher_check_depends_on_exactly_one_property(tmp_path):
    """Neither cipher property may drive both checks.

    The first version of this check scored filenames_mode as well, which the
    filenames cipher check already scores, so an Adiantum device got
    two findings for one condition. The invariant that prevents it is not
    "the two never fire together": contents and filenames are independent
    settings and can genuinely both be wrong. It is that each verdict is a
    function of one property alone, so no single value is scored twice.
    """
    _skip_without_posix_shell()
    other = _overlay_check("Userdata Filenames Encryption Cipher")
    CONTENTS = ("aes-256-xts", "adiantum", "aes-128-cbc", "")
    FILENAMES = ("aes-256-cts", "aes-256-hctr2", "adiantum", "")

    def verdicts(contents, filenames):
        props = {"ro.crypto.type": "file", "ro.build.version.sdk": "34"}
        if contents:
            props["ro.crypto.volume.contents_mode"] = contents
        if filenames:
            props["ro.crypto.volume.filenames_mode"] = filenames
        _, mine = _run_fbe(tmp_path, props)
        env = dict(os.environ, PATH=str(tmp_path / "bin") + os.pathsep
                   + os.environ.get("PATH", ""))
        out = subprocess.run(["sh", "-c", other["command"]], capture_output=True,
                             text=True, env=env).stdout.strip()
        return mine, bool(re.search(other["safe_pattern"], out, re.M))

    # This check's verdict must be constant across every filenames value.
    for contents in CONTENTS:
        seen = {verdicts(contents, f)[0] for f in FILENAMES}
        assert len(seen) == 1, (
            "contents=%r gives different verdicts depending on filenames_mode: %s"
            % (contents, seen))

    # The filenames check's verdict must be constant across every contents value.
    for filenames in FILENAMES:
        seen = {verdicts(c, filenames)[1] for c in CONTENTS}
        assert len(seen) == 1, (
            "filenames=%r gives different verdicts depending on contents_mode: %s"
            % (filenames, seen))


def test_key_size_comes_from_the_key_not_the_signature(tmp_path):
    """The reported size must be key_num_bits from the public key blob.

    The first version of this check computed signature_size * 8, which is an
    inference from the signature rather than a reading of the key. This image
    carries a 2048-bit key with a header claiming a 4096-bit signature: the
    old arithmetic would call it strong.
    """
    img = _avb_image(tmp_path / "lie.img", 2, 512, key_bits=2048)
    out, safe = _run_avb(KEY_CHECK, tmp_path, img)
    assert not safe, out
    assert "avb_key=MISMATCH" in out, out
    assert "key_bits=2048" in out and "sig_bits=4096" in out, out


def test_both_key_and_signature_sizes_are_reported(tmp_path):
    """A verdict the reader can check needs both numbers on the row."""
    img = _avb_image(tmp_path / "ok.img", 2, 512)
    out, safe = _run_avb(KEY_CHECK, tmp_path, img)
    assert safe, out
    assert "key_bits=4096" in out and "sig_bits=4096" in out, out


def test_signed_header_with_no_public_key_is_unmeasured(tmp_path):
    """algorithm_type says signed but public_key_size is 0. There is no key to
    measure, so the honest answer is unmeasured rather than a strength call."""
    import struct
    b = bytearray(256)
    b[0:4] = b"AVB0"
    struct.pack_into(">II", b, 4, 1, 0)
    struct.pack_into(">Q", b, 12, 544)
    struct.pack_into(">I", b, 28, 2)              # claims SHA256_RSA4096
    struct.pack_into(">QQ", b, 48, 32, 512)
    struct.pack_into(">QQ", b, 64, 0, 0)          # but no public key
    out, safe = _run_avb(KEY_CHECK, tmp_path, raw=bytes(b) + b"\x00" * 1024)
    assert not safe, out
    assert hardax.isUnmeasured(out) == "UNMEASURED", out
    assert "public_key_size is 0" in out, out


# --------------------------------------------------------------------------
# v1-only APK signatures (APP-SIGV1ONLY-001)
# --------------------------------------------------------------------------

SIGV1_CHECK = "Packages Without a v2 or Newer APK Signature"
_APK_SIG_MAGIC = b"APK Sig Block 42"


def _sig_apk(path, v2=False):
    """A minimal APK, optionally carrying a real APK Signing Block.

    The block sits between the last local file entry and the central
    directory: an 8-byte length, the payload, the same length again, then the
    16-byte magic, whose final byte is the one immediately before the central
    directory. Inserting it shifts the directory, so the offset in the End of
    Central Directory record has to be rewritten or the archive is corrupt and
    the check counts it unparsed rather than signed.
    """
    import io
    import struct
    import zipfile
    buf = io.BytesIO()
    z = zipfile.ZipFile(buf, "w")
    z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00" + b"\x00" * 200)
    z.writestr("classes.dex", b"dex\n035\x00" + b"\x41" * 2000)
    z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    z.writestr("META-INF/CERT.SF", "Signature-Version: 1.0\n")
    z.writestr("META-INF/CERT.RSA", b"\x30\x82" + b"\x00" * 800)
    z.close()
    data = bytearray(buf.getvalue())
    if v2:
        eocd = data.rfind(b"PK\x05\x06")
        cd = struct.unpack_from("<I", data, eocd + 16)[0]
        payload = b"\x55" * 256
        blocklen = len(payload) + 8 + len(_APK_SIG_MAGIC)
        block = (struct.pack("<Q", blocklen) + payload
                 + struct.pack("<Q", blocklen) + _APK_SIG_MAGIC)
        data = bytearray(bytes(data[:cd]) + block + bytes(data[cd:]))
        eocd = data.rfind(b"PK\x05\x06")
        struct.pack_into("<I", data, eocd + 16, cd + len(block))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(bytes(data))
    return path


def _run_sigv1(tmp_path, specs):
    """specs: list of (name, v2). Builds a fake app tree and runs the check."""
    _skip_without_posix_shell()
    chk = _overlay_check(SIGV1_CHECK)
    root = tmp_path / "root"
    (root / "data" / "app").mkdir(parents=True, exist_ok=True)
    for name, v2 in specs:
        _sig_apk(root / "data" / "app" / name / "base.apk", v2=v2)
    cmd = chk["command"].replace('"/data/app ', '"%s/data/app ' % root)
    for p in ("/system/app", "/system/priv-app", "/vendor/app",
              "/product/app", "/system_ext/app"):
        cmd = cmd.replace(p, str(root) + p)
    out = subprocess.run(["sh", "-c", cmd], capture_output=True,
                         text=True).stdout.strip()
    return out, bool(re.search(chk["safe_pattern"], out, re.M))


def test_v2_signed_packages_read_clean(tmp_path):
    out, safe = _run_sigv1(tmp_path, [("a", True), ("b", True)])
    assert safe, out
    assert "v1_only=0 v2plus=2" in out, out


def test_v1_only_package_is_caught_among_v2_ones(tmp_path):
    """Janus (CVE-2017-13156) needs v1 as the only scheme. One legacy package
    in a fleet of correctly signed ones has to surface, and be named."""
    out, safe = _run_sigv1(tmp_path, [("modern", True), ("legacy", False)])
    assert not safe, out
    assert "v1_only=1 v2plus=1" in out, out
    assert "legacy" in out, out


def test_signing_block_is_located_structurally_not_searched(tmp_path):
    """The magic is matched at the 16 bytes before the central directory, not
    found by scanning. A copy of the magic elsewhere in the archive must not
    make a v1-only package look signed: GNU and busybox grep disagree on
    binary input, which is why a byte search was rejected.
    """
    out, safe = _run_sigv1(tmp_path, [("decoy", False)])
    assert not safe, out
    p = tmp_path / "root" / "data" / "app" / "decoy" / "base.apk"
    # Plant the magic inside a stored entry, away from the directory edge.
    import io
    import zipfile
    buf = io.BytesIO()
    z = zipfile.ZipFile(buf, "w")
    z.writestr("assets/decoy.bin", _APK_SIG_MAGIC * 4)
    z.writestr("META-INF/CERT.SF", "Signature-Version: 1.0\n")
    z.close()
    p.write_bytes(buf.getvalue())
    out, safe = _run_sigv1(tmp_path, [])
    assert not safe, out
    assert "v1_only=1" in out or hardax.isUnmeasured(out), out


def test_zip_comment_counts_as_unparsed_not_signed(tmp_path):
    """A trailing comment moves the End of Central Directory record, so the
    fixed-offset read no longer lands on it. That must be reported as unparsed
    rather than guessed either way."""
    out, _ = _run_sigv1(tmp_path, [("c", True)])
    p = tmp_path / "root" / "data" / "app" / "c" / "base.apk"
    p.write_bytes(p.read_bytes() + b"trailing comment bytes")
    out, safe = _run_sigv1(tmp_path, [])
    assert not safe, out
    assert hardax.isUnmeasured(out) == "UNMEASURED", out


def test_no_readable_apk_is_unmeasured_not_zero(tmp_path):
    """The false-clean case: nothing parsed must not report v1_only=0."""
    out, safe = _run_sigv1(tmp_path, [])
    assert not safe, out
    assert hardax.isUnmeasured(out) == "UNMEASURED", out


# --------------------------------------------------------------------------
# Legacy targetSdkVersion (APP-TARGETSDK-001)
# --------------------------------------------------------------------------

TARGETSDK_CHECK = "Packages Targeting an SDK Below the Cleartext Default"


def _run_targetsdk(dumpsys_output):
    """Run the real command with dumpsys stubbed to the given text."""
    _skip_without_posix_shell()
    chk = _overlay_check(TARGETSDK_CHECK)
    stub = "D=$(cat <<'XEOF'\n%s\nXEOF\n)" % dumpsys_output
    cmd = chk["command"].replace("D=$(dumpsys package packages 2>/dev/null)", stub)
    out = subprocess.run(["sh", "-c", cmd], capture_output=True,
                         text=True).stdout.strip()
    return out, bool(re.search(chk["safe_pattern"], out, re.M))


def test_all_modern_targets_read_clean():
    out, safe = _run_targetsdk("Package [a] targetSdk=34\nPackage [b] targetSdk=28")
    assert safe, out
    assert "legacy_targetsdk=0 of 2" in out, out


def test_package_below_the_cleartext_default_is_caught():
    """targetSdk under 28 gets cleartext permitted by default, so such a
    package can ship no network security config, satisfy the NSC checks, and
    still send plaintext."""
    out, safe = _run_targetsdk("Package [a] targetSdk=34\nPackage [b] targetSdk=22")
    assert not safe, out
    assert "legacy_targetsdk=1 of 2" in out, out
    assert "min_observed=22" in out, out


def test_exactly_28_is_not_a_finding():
    """The boundary is the point of the check: 28 is where the default flips."""
    out, safe = _run_targetsdk("Package [a] targetSdk=28")
    assert safe, out
    out, safe = _run_targetsdk("Package [a] targetSdk=27")
    assert not safe, out


def test_dead_binder_is_unmeasured_not_zero():
    out, safe = _run_targetsdk("")
    assert not safe, out
    assert hardax.isUnmeasured(out) == "UNMEASURED", out


def test_dumpsys_answering_without_values_is_unmeasured():
    """An answer with no targetSdk in it is not a fleet of zero legacy
    packages. Counting it as clean is the false-clean defect."""
    out, safe = _run_targetsdk("Packages:\n  nothing useful here\n")
    assert not safe, out
    assert hardax.isUnmeasured(out) == "UNMEASURED", out


def test_targetsdk_is_gated_rather_than_guessing_without_binder():
    """The value is a typed integer in the binary manifest, not a string in
    the pool, so there is no file-based fallback. Verified against a real APK:
    the attribute name is in the pool, no SDK level is. The check must be
    reported as not applicable rather than degrade to a guess.
    """
    chk = _overlay_check(TARGETSDK_CHECK)
    assert hardax.commandNeedsBinder(chk["command"])
    assert not chk.get("binder_optional", False)
    rows, _ = hardax.runChecks(
        FakeDevice(default=""), [chk], capabilities={"binder": False})
    assert rows[0]["status"] == "SKIPPED", rows[0]["status"]
