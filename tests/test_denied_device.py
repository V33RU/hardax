"""Every check, executed with every probe failing.

The defects this file exists to prevent were not design problems, they were
shell mistakes: a `grep -c` that never looked at the mount point, a `^/dev/loop`
anchor that matched nothing on Android, an `[ -n "$X" ] &&` with no else branch,
and an `else echo Permissive` that declared SELinux off when it could not look.
None of it was caught, because the suite only validated JSON shape and ran
`sh -n`. Nothing ever executed a check against a device that says no.

So this does. Each command runs for real with:

  * every Android tool on PATH exiting 1 with no output (binder denied, SELinux
    denied, tool absent -- the engine cannot tell these apart and neither can
    the check),
  * every absolute Android path redirected into an empty directory, so a read
    fails the way a denied read fails.

Under those conditions a check may report VERIFY, SKIPPED, INFO or SAFE. It may
NOT report CRITICAL or WARNING, because it measured nothing. A finding raised
here is a finding raised on a real device that simply denied the probe, and
that is the bug that made 524 SAFE results on the reference panel untrustworthy.
"""

import io
import os
import re
import sys
import shutil
import contextlib
import subprocess

import pytest

import hardax
from conftest import load_all_checks, REPO_ROOT

# The harness executes real commands against a real filesystem: stub tools are
# POSIX shell scripts with a shebang and an exec bit, and the reroot rewrites
# absolute paths like /proc and /vendor. None of that is meaningful on Windows,
# where `sh` may be present via Git Bash but the path and permission semantics
# are not. Skip the module rather than assert on a platform it cannot model.
pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or not shutil.which("sh"),
    reason="needs a POSIX shell and filesystem semantics")

FIXTURES = os.path.join(REPO_ROOT, "tests", "fixtures")
DENIED_BIN = os.path.join(FIXTURES, "denied_bin")

# Absolute roots a check may read. Redirected into an empty tree so that a read
# fails rather than hitting the host OS, which would otherwise answer for Linux
# and mask the check's behaviour on Android.
ANDROID_ROOTS = ("/proc", "/sys", "/vendor", "/system", "/odm", "/product",
                 "/metadata", "/cache", "/apex", "/firmware", "/data", "/sdcard",
                 "/storage", "/mnt", "/dev", "/first_stage_ramdisk", "/persist",
                 # Android-only executable roots. Without these the harness reads
                 # the host's real /sbin, where a Linux workstation genuinely has
                 # mtd_debug, nanddump and friends.
                 "/sbin", "/su", "/debug_ramdisk")

# /dev/null and friends must keep working: they are shell plumbing, not device
# state, and redirecting them into a directory that does not exist turns every
# `2>/dev/null` into a shell error rather than a silenced probe.
_KEEP = ("null", "stdout", "stderr", "zero", "tty", "full", "random", "urandom")

_SPLIT = re.compile(r"(?<![\w/])(%s)(?!/(?:%s)\b)(?=[/\s'\"*;)]|$)"
                    % ("|".join(re.escape(r) for r in ANDROID_ROOTS),
                       "|".join(_KEEP)))


def reroot(command, root):
    return _SPLIT.sub(lambda m: root + m.group(1), command)


class _Canned(hardax.Device):
    def __init__(self, result):
        self.result = result

    def shellEx(self, command):
        return self.result

    def shell(self, command):
        return self.result.merged

    def idString(self):
        return "denied-device"


@pytest.fixture(scope="module")
def empty_root(tmp_path_factory):
    return str(tmp_path_factory.mktemp("denied_root"))


@pytest.fixture(scope="module")
def denied_bin(tmp_path_factory):
    """A read-only copy of the stubs.

    Read-only because `Writable Paths in $PATH` legitimately reports a writable
    PATH entry, and a fixture directory owned by the test user would otherwise
    make the harness itself the finding. `su` and `magisk` are deliberately
    absent: a stub named `su` on PATH is a real root indicator, not a denied
    probe.
    """
    d = tmp_path_factory.mktemp("denied_bin")
    for name in sorted(os.listdir(DENIED_BIN)):
        dst = d / name
        shutil.copy2(os.path.join(DENIED_BIN, name), str(dst))
        os.chmod(str(dst), 0o555)
    os.chmod(str(d), 0o555)
    yield str(d)
    os.chmod(str(d), 0o755)


def run_denied(check, empty_root, denied_bin=DENIED_BIN):
    """Execute one check with every probe failing; return its engine status."""
    env = {"PATH": denied_bin + ":/usr/bin:/bin", "LC_ALL": "C",
           "HOME": empty_root}
    try:
        proc = subprocess.run(["sh", "-c", reroot(check["command"], empty_root)],
                              capture_output=True, text=True, timeout=15,
                              cwd=empty_root, env=env)
        res = hardax.ShellResult(proc.stdout, proc.stderr, proc.returncode)
    except subprocess.TimeoutExpired:
        res = hardax.ShellResult("", "[timeout]", 124)
    with contextlib.redirect_stdout(io.StringIO()):
        rows, _ = hardax.runChecks(_Canned(res), [check])
    return rows[0]["status"], res.out.strip()


# Checks excluded from the rule below. Kept empty deliberately: an exclusion
# here is almost always the harness modelling a device that cannot exist rather
# than a check that is allowed to misbehave. Two earlier entries were removed by
# fixing the stub set instead -- `which` now exits 1 (so `Root Access (su)` sees
# no su on PATH, as on a denied device, rather than this host's /usr/bin/su),
# and `selinuxenabled`/`sestatus` are no longer stubbed at all because they are
# Linux userspace tools that do not ship on Android, so the check reaches its
# real NO_TOOL path.
HOST_TRUE_POSITIVES = {}


def test_no_check_reports_a_finding_when_every_probe_fails(empty_root, denied_bin):
    offenders = []
    for check in load_all_checks():
        if check["label"] in HOST_TRUE_POSITIVES:
            continue
        status, out = run_denied(check, empty_root, denied_bin)
        if status in ("CRITICAL", "WARNING"):
            offenders.append(
                "  %s [%s]\n      level=%s status=%s\n      printed: %r\n"
                "      safe_pattern: %r"
                % (check["_file"], check["label"], check["level"], status,
                   out[:120], check["safe_pattern"]))
    assert not offenders, (
        "%d check(s) report a finding having measured nothing.\n"
        "Give the failing path a branch that emits one of %s, which the engine "
        "routes to VERIFY:\n\n%s"
        % (len(offenders), sorted(hardax.UNMEASURED_TOKENS), "\n".join(offenders)))


def test_the_harness_itself_still_detects_a_bad_check(empty_root, denied_bin):
    """Guard the guard: a deliberately careless check must be caught here."""
    careless = {
        "category": "TEST", "label": "careless", "level": "critical",
        "description": "d", "safe_pattern": "^Enforcing$",
        # the exact shape that shipped in selinux.json
        "command": ('if [ -r /sys/fs/selinux/enforce ]; then '
                    'cat /sys/fs/selinux/enforce; else echo Permissive; fi'),
    }
    status, out = run_denied(careless, empty_root, denied_bin)
    assert status == "CRITICAL" and out == "Permissive"
