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


# Commands that would be a subshell, not an arithmetic operand, if they appear
# straight after "$((". Matching known command names rather than guessing at
# operand names keeps `$((N+1))` and `$((PY * 12))` out of the results.
SUBSHELL_COMMANDS = (
    "ps", "netstat", "ss", "cat", "ls", "find", "grep", "dumpsys", "getprop",
    "readelf", "awk", "sed", "pm", "settings", "cmd", "service", "mount",
)


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


def test_tree_searches_do_not_hide_an_incomplete_walk():
    """A `find` over a directory tree must not combine stderr suppression with
    empty_is_safe.

    The engine keeps stdout and stderr apart, so a walk that produced no hits
    and a page of "Permission denied" is reported as a failed probe rather than
    a clean result. Suppressing that stderr throws the distinction away, and
    the check passes on a device where the tree was never fully searched. This
    was observed on an Android 13 device whose shell could read only part of
    /system: every SUID, world-writable and credential hunt reported clean.

    Note the inverse rule still applies to *existence* checks: for `ls /path`
    asking whether one bad file is present, "No such file or directory" is the
    answer, so those keep their redirect.
    """
    tree = re.compile(r"\bfind\s+(?:/\S+\s+)+")
    offenders = []
    for c in load_all_checks():
        cmd = c["command"]
        if not tree.search(cmd) or not c.get("empty_is_safe"):
            continue
        head = cmd.partition("|")[0]
        if "2>/dev/null" in head:
            offenders.append(f"  {c['_file']} [{c['label']}]")
    assert not offenders, (
        "find-over-tree checks where a partial walk passes silently:\n"
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
    production Android builds. A check that reads it must say so explicitly
    rather than returning empty.

    The engine now routes an UNMEASURED / NOT_OBSERVABLE declaration to VERIFY
    regardless of the safe_pattern, so the declaration is what matters here,
    not whether the pattern accepts it. Keeping the token in the pattern is
    still required so the intent is readable at the check definition.
    """
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
    assert len(counts) == 29, f"category count changed: {sorted(counts)}"
    thin = {cat: n for cat, n in counts.items() if n < 3}
    assert not thin, f"categories reduced to almost nothing: {thin}"


def test_no_count_and_list_pairs_of_the_same_probe():
    """Three pairs shipped where one check ran a probe and a second ran the
    identical probe piped to `wc -l`. Both fired on the same condition, so a
    single planted artifact or injected CA produced two findings.

    Report the count and the detail from one check instead of splitting them.
    """
    def strip_count(cmd):
        c = re.sub(r"\s*\|\s*wc\s+-l\s*$", "", cmd.strip())
        return re.sub(r"\s+", " ", c.replace("2>/dev/null", "")).strip()

    by_file = defaultdict(list)
    for c in load_all_checks():
        by_file[c["_file"]].append(c)

    pairs = []
    for fname, checks in by_file.items():
        seen = {}
        for c in checks:
            key = strip_count(c["command"])
            prev = seen.get(key)
            if prev is not None and prev["command"] != c["command"]:
                # An info/verify evidence collector paired with a failable
                # check is fine: one reports the value, the other decides.
                # Two failable checks on one probe raise two findings for one
                # condition, which is the defect.
                if prev["level"] in FAILABLE and c["level"] in FAILABLE:
                    pairs.append(f"  {fname}: {prev['label']!r} and {c['label']!r}\n"
                                 f"      both {prev['level']}/{c['level']} on: {key[:80]}")
            seen.setdefault(key, c)
    assert not pairs, (
        "two failable checks running the same probe, one counting one listing:\n"
        + "\n".join(pairs))


def test_no_subshell_opened_as_arithmetic_expansion():
    """`$((` opens arithmetic expansion, not a command substitution wrapping a
    subshell. A command written as `$((cmd_a || cmd_b) | filter)` is parsed by
    POSIX sh as arithmetic on a command name and the whole check fails.

    This has bitten twice: once on a netstat alternation, and once when the
    ps/BusyBox fallback was introduced. `sh -n` catches it, but only if the
    surrounding syntax happens to be invalid, so pin it directly.
    """
    pattern = re.compile(
        r"\$\(\(\s*(?:/\w[\w/.-]*/)?(" + "|".join(SUBSHELL_COMMANDS) + r")\b")
    offenders = []
    for c in load_all_checks():
        for m in pattern.finditer(c["command"]):
            offenders.append(f"  {c['_file']} [{c['label']}]: $(({m.group(1)} ...")
    assert not offenders, (
        "subshell opened as arithmetic expansion, write '$( (' instead:\n"
        + "\n".join(offenders))


def test_counting_checks_do_not_treat_empty_as_safe():
    """A check whose command always prints a number (`wc -l`, `grep -c`, or a
    `|| echo 0` fallback) cannot legitimately produce empty output. If it does,
    the command failed outright, so empty_is_safe can only mask a failed probe.

    Found on a device where /proc/cmdline was unreadable: the critical
    dm-verity check returned empty and was reported SAFE.
    """
    counting = re.compile(r"\|\s*wc\s+-l|grep\s+(?:-\w*\s+)*-\w*c\w*\s|\|\|\s*echo\s+0")
    offenders = []
    for c in load_all_checks():
        if not c.get("empty_is_safe") or c["level"] not in FAILABLE:
            continue
        if counting.search(c["command"]):
            offenders.append(f"  {c['_file']} [{c['label']}]: {c['safe_pattern']}")
    assert not offenders, (
        "counting checks where empty output is scored SAFE:\n" + "\n".join(offenders))


@pytest.mark.skipif(not shutil.which("sh"), reason="POSIX sh not available")
def test_inner_sh_c_scripts_also_parse():
    """`sh -n` on `sh -c '<script>'` only validates the outer wrapper, so a
    broken inner script passes the syntax gate and fails on the device instead.

    That happened to "No Individual Permissive Domains", which carried a '#'
    comment inside a single-line script. The comment swallowed the rest of the
    line including `else` and `fi`, and the device answered
    "sh: syntax error: unmatched 'if'" while CI stayed green.
    """
    inner = re.compile(r"^\s*sh\s+-c\s+'(.*)'\s*$", re.DOTALL)
    broken = []
    for c in load_all_checks():
        m = inner.match(c["command"])
        if not m:
            continue
        script = m.group(1)
        proc = subprocess.run(["sh", "-n"], input=script,
                              capture_output=True, text=True)
        if proc.returncode != 0:
            broken.append(f"  {c['_file']} [{c['label']}]: {proc.stderr.strip()}")
    assert not broken, (
        "inner sh -c scripts that do not parse:\n" + "\n".join(broken))


def test_no_comment_inside_single_line_script():
    """A '#' comment in a one-line command comments out everything after it,
    including the terminators of any open if/for/while block."""
    offenders = []
    for c in load_all_checks():
        cmd = c["command"]
        if "\n" in cmd:
            continue
        # a '#' that starts a word, is not inside a character class, and is not
        # a shell special like ${#x} or $#
        for m in re.finditer(r"(?:^|\s)#\s", cmd):
            offenders.append(f"  {c['_file']} [{c['label']}]: ...{cmd[max(0,m.start()-30):m.start()+40]}...")
    assert not offenders, (
        "single-line commands containing a '#' comment:\n" + "\n".join(offenders))


def test_grep_patterns_use_no_gnu_regex_extensions():
    """bionic's regcomp is OpenBSD-derived and implements POSIX only. GNU
    extensions silently become literals rather than erroring, so the check runs,
    matches nothing, and reports a clean device.

    Confirmed on an Android 13 device:
      grep -Ec "\\bselinuxfs\\b" /proc/mounts -> 0   (the line is there)
      printf "a b" | grep -Ec "a\\sb"         -> 0
    \\| cost 31 checks, \\b cost 14, \\s cost 2. Use POSIX classes and explicit
    boundaries instead: [[:space:]], [[:alnum:]_], ([^0-9]|$).

    Note safe_pattern is evaluated by Python, where these DO work, so this
    applies only to patterns handed to the device's grep.
    """
    gnu = {r"\b": "word boundary", r"\<": "word start", r"\>": "word end",
           r"\w": r"\w", r"\s": r"\s", r"\d": r"\d", r"\|": "alternation"}
    offenders = []
    for c in load_all_checks():
        for m in re.finditer(r"""grep\s+(?:-\w+\s+)*(['"])(.*?)\1""", c["command"]):
            pat = m.group(2)
            for esc, name in gnu.items():
                if esc in pat:
                    offenders.append(f"  {c['_file']} [{c['label']}]: {name} in {pat[:50]}")
    assert not offenders, (
        "GNU regex extensions in device grep patterns:\n" + "\n".join(sorted(set(offenders))))


def test_grep_c_does_not_double_its_count():
    """`grep -c` prints 0 AND exits 1 when nothing matches, so a `|| echo 0`
    fallback appends a SECOND zero:

        $ printf 'abc\\n' | { grep -c '^zzz' || echo 0; }
        0
        0

    That reached the report as `nf_tables_loaded=0\\n0` on a critical CVE check.
    Use `| head -1` and default the variable instead, which also covers the
    genuinely-empty case where the file is missing and grep exits 2.
    """
    pat = re.compile(r"grep\s+(?:-\w*\s+)*-\w*c\w*\s[^|;)]*?\|\|\s*echo\s+0")
    offenders = [f"  {c['_file']} [{c['label']}]"
                 for c in load_all_checks() if pat.search(c["command"])]
    assert not offenders, (
        "grep -c with a redundant '|| echo 0' fallback:\n" + "\n".join(offenders))


def test_count_emitting_checks_can_still_pass():
    """A check that prints `count=N` must have a safe_pattern that can match
    SOME count value, otherwise it reports a finding on every device forever.

    Introduced while adding evidence to verdict-only checks: the output format
    changed from a bare number to `count=N` and three safe_patterns were left
    as `^[0-5]$` / `^0$`, which no `count=N` string can ever satisfy.

    The assertion is deliberately not "must match count=0". For a count of bad
    things zero is the clean state, but for a count of good things (partitions
    protected by dm-verity, say) zero is the finding. Requiring count=0 to pass
    would forbid that second, legitimate shape.
    """
    offenders = []
    for c in load_all_checks():
        if 'echo "count=' not in c["command"]:
            continue
        try:
            ok = any(re.search(c["safe_pattern"], f"count={n}", re.I | re.M)
                     for n in (0, 1, 2, 5, 9, 42, 999))
        except re.error:
            ok = False
        if not ok:
            offenders.append(f"  {c['_file']} [{c['label']}]: {c['safe_pattern']}")
    assert not offenders, (
        "checks emitting count=N whose safe_pattern can never match any count:\n"
        + "\n".join(offenders))
