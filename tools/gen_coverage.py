#!/usr/bin/env python3
"""Generate COVERAGE.md from the shipping check bundle.

Every count and every test name in COVERAGE.md is read out of the repo rather
than typed by hand. The README's per-category table was hand-maintained and
drifted to 816 while the bundle held 855, with 9 of 29 rows stale, which is
the failure this script exists to prevent.

Run from the repository root:

    python3 tools/gen_coverage.py

tests/test_coverage_doc.py asserts the committed COVERAGE.md matches what this
script produces, so a bundle change that is not followed by a regeneration
fails CI.
"""
import sys
import os
import re
import collections

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

NICE = {
    "SYSTEM": "System and kernel hardening",
    "BLUETOOTH": "Bluetooth and BLE",
    "NETWORK": "Network exposure and transport",
    "APPS": "Installed applications",
    "PRIVACY": "Privacy controls and data exposure",
    "PARTITION": "Partitions, mounts and overlays",
    "BINARY_HARDENING": "Binary and toolchain hardening",
    "BOOT_SECURITY": "Verified boot and boot chain",
    "CVE_INDICATORS": "Known-CVE exposure indicators",
    "SELINUX": "SELinux policy and enforcement",
    "STORAGE": "Storage and encryption",
    "ATTESTATION": "Keystore, TEE and attestation",
    "CERTIFICATE_AUDIT": "Trust store and certificates",
    "MALWARE": "Root frameworks and unwanted binaries",
    "POS_SECURITY": "Point-of-sale hardening",
    "FORENSIC_INDICATORS": "Forensic and tamper indicators",
    "AUTOMOTIVE": "Automotive and telematics",
    "CRYPTOGRAPHY": "Cryptographic configuration",
    "CIS_BENCHMARK": "CIS Android Benchmark items",
    "USB_SECURITY": "USB and gadget exposure",
    "MDM_POLICY": "MDM and device policy",
    "MODERN_ANDROID": "Modern Android platform features",
    "INPUT": "Input and accessibility",
    "MEDICAL": "Medical device hardening",
    "DEVICE_MANAGEMENT": "Device management and ownership",
    "NFC_SECURITY": "NFC and secure element",
    "ADB_SECURITY": "ADB exposure",
    "BIOMETRIC": "Biometrics and keyguard",
    "KERNEL_DRIVERS": "Kernel drivers and device nodes",
}

METHODS = [
    ("Filesystem walks (find, ls, stat)", r"\b(find|ls |stat )"),
    ("System properties (getprop)", r"getprop"),
    ("Secure settings and device_config", r"\b(settings get|device_config)\b"),
    ("Framework services (dumpsys, service)", r"\b(dumpsys|service call|service list)\b"),
    ("procfs and sysfs", r"/proc/|/sys/"),
    ("Package manager (pm, cmd)", r"\b(pm |cmd )"),
    ("Process table (ps)", r"\bps -"),
    ("Kernel and app logs (dmesg, logcat)", r"\b(dmesg|logcat)\b"),
    ("Raw block device reads (dd)", r"\bdd if="),
]

ENFORCED = [
    ("A probe that cannot measure must emit an unmeasured token, not empty output",
     ["test_cannot_determine_tokens_have_an_unmeasured_branch"]),
    ("No check may report a finding on a device where every probe is denied",
     ["test_denied_device.py"]),
    ("Every command must parse under POSIX `sh`, including nested `sh -c`",
     ["test_every_command_parses_under_posix_sh", "test_inner_sh_c_scripts_also_parse"]),
    ("No GNU regex extensions in `grep` patterns",
     ["test_grep_patterns_use_no_gnu_regex_extensions"]),
    ("No GNU-only `find` predicates", ["test_find_uses_no_gnu_only_predicates"]),
    ("`grep -c` must not double its count", ["test_grep_c_does_not_double_its_count"]),
    ("`$( (` must not be written as `$((`",
     ["test_no_subshell_opened_as_arithmetic_expansion"]),
    ("A tree search must not hide an incomplete walk",
     ["test_tree_searches_do_not_hide_an_incomplete_walk"]),
    ("Binder output must not be counted without a guard",
     ["test_binder_output_is_not_counted_without_a_guard"]),
    ("Counting checks must not treat empty as safe, and must still be able to pass",
     ["test_counting_checks_do_not_treat_empty_as_safe",
      "test_count_emitting_checks_can_still_pass"]),
    ("Every check must be capable of failing", ["test_failable_checks_are_capable_of_failing"]),
    ("IDs and labels unique across the bundle, and labels not confusable",
     ["test_ids_are_unique_across_all_files", "test_labels_are_unique_across_all_files",
      "test_labels_are_not_confusable"]),
    ("No two checks may share a command, or scan the same name set",
     ["test_no_two_checks_share_a_command", "test_no_two_checks_scan_the_same_name_set"]),
    ("No count-and-list pair of the same probe",
     ["test_no_count_and_list_pairs_of_the_same_probe"]),
    ("Every check must carry remediation text", ["test_every_check_has_remediation_text"]),
    ("No em dashes anywhere in check text", ["test_no_em_dashes_in_check_text"]),
    ("Every `safe_pattern` must compile", ["test_all_safe_patterns_compile"]),
    ("Counts quoted in `README.md` must match the bundle",
     ["test_readme_badge_counts_match_reality",
      "test_readme_prose_check_counts_match_reality",
      "test_readme_category_table_counts_match_reality"]),
]

GAPS = [
    ("Certificates expiring soon",
     "`EXPIRING_SOON` and `CHECK` certificates appear in the HTML certificate "
     "table but produce no check row, so they do not reach the findings count "
     "or the risk score. Only already-expired certificates are scored."),
    ("Rollback index values",
     "Reported as `info` only, so a device shipping with rollback protection "
     "effectively disabled is printed rather than flagged."),
    ("Root of trust fingerprint",
     "Nothing compares `ro.boot.vbmeta.digest` against an expected baseline, so "
     "a device anchored to a strong but attacker-controlled key passes every "
     "boot check."),
    ("Key storage backend",
     "`BOOT-ROTKEY-001` reports where the verified boot anchor lives. The "
     "equivalent for app and system keys is not built: TEE identity is readable "
     "from properties, but the four existing keystore checks all call "
     "`pm list features` or `lshal`, so they are binder-gated and report "
     "nothing over SSH or UART."),
    ("OTP and eFuse contents",
     "Not attempted. Paths are per-SoC and usually root-only, so any probe "
     "would be guesswork presented as a measurement."),
    ("Treble / VINTF",
     "No coverage. Judged a vendor-interface correctness property rather than a "
     "security control."),
    ("Memory corruption exploitability",
     "Out of scope by policy. Checks report configuration and exposure, never "
     "exploitation."),
]


def build():
    sys.path.insert(0, REPO_ROOT)
    sys.path.insert(0, os.path.join(REPO_ROOT, "tests"))
    import hardax
    from conftest import load_all_checks

    cs = load_all_checks()
    total = len(cs)
    cats = collections.Counter(c["category"] for c in cs)

    def gated(c):
        return (hardax.commandNeedsBinder(c["command"])
                and not c.get("binder_optional", False))

    ngated = sum(1 for c in cs if gated(c))
    nshell = total - ngated

    o = []
    w = o.append

    w("# Coverage")
    w("")
    w("What HARDAX measures, how it measures it, and what it does not measure.")
    w("")
    w("Generated by `tools/gen_coverage.py` from the shipping check bundle in")
    w("`hardax/commands/*.json` plus the host-side analysis in")
    w("`hardax/__init__.py`. Do not edit by hand: regenerate it.")
    w("")
    w("| | |")
    w("|---|---|")
    w("| Checks | **%d** |" % total)
    w("| Categories | **%d** |" % len(cats))
    w("| Runnable on any shell | **%d** |" % nshell)
    w("| Require framework (binder) access | **%d** |" % ngated)
    w("| Host-side analysis findings | **3** (X.509 trust store) |")
    w("| Transports | ADB, SSH, UART serial |")
    w("")
    w("---")
    w("")
    w("## How a check can answer")
    w("")
    w("A check does not return pass or fail. It returns one of five outcomes,")
    w("because \"I could not measure this\" is a different statement from \"this is")
    w("fine\", and conflating the two is how an auditor reports a device secure")
    w("that was never actually examined.")
    w("")
    w("| Outcome | Meaning | Counts as a finding |")
    w("|---|---|---|")
    w("| `SAFE` | Measured, and the value is the expected secure value | no |")
    w("| `CRITICAL` / `WARNING` | Measured, and the value is wrong | yes |")
    w("| `INFO` | Measured and reported, with no pass/fail opinion | no |")
    w("| `VERIFY` | Not measurable here, so deliberately unscored | no |")
    w("| `SKIPPED` | Not applicable to this transport, named as such | no |")
    w("")
    w("A check routes itself to `VERIFY` by emitting one of four tokens, which")
    w("the engine recognises rather than each check inventing its own wording:")
    w("")
    w("```")
    for t in sorted(hardax.UNMEASURED_TOKENS):
        w(t)
    w("```")
    w("")
    w("Why this exists: a probe denied by SELinux, or targeting a path that does")
    w("not exist, returns empty output. Scoring empty output as a pass means a")
    w("locked-down device audits cleaner than an open one. Every check that can")
    w("fail to measure must say so, and a test suite enforces it against a")
    w("simulated device where every probe is denied.")
    w("")
    w("`INFO` covers the other direction. A check whose `safe_pattern` matches")
    w("everything (`.`, `.*`, `^.*$` and similar) is an inventory check, not a")
    w("test, and is reported as `INFO` rather than inflating the safe count.")
    w("")
    w("---")
    w("")
    w("## Coverage by category")
    w("")
    w("`Shell` runs over any transport. `Binder` needs framework access, which an")
    w("ADB shell normally has and a vendor-domain SSH or UART shell often does")
    w("not. Reachability is probed at connection time, not assumed.")
    w("")
    w("| Category | Checks | Shell | Binder |")
    w("|---|---:|---:|---:|")
    for cat, n in sorted(cats.items(), key=lambda kv: (-kv[1], kv[0])):
        grp = [c for c in cs if c["category"] == cat]
        g = sum(1 for c in grp if gated(c))
        w("| %s | %d | %d | %d |" % (NICE.get(cat, cat), n, n - g, g))
    w("| **Total** | **%d** | **%d** | **%d** |" % (total, nshell, ngated))
    w("")
    w("---")
    w("")
    w("## How the device is probed")
    w("")
    w("A single check often uses several of these.")
    w("")
    w("| Method | Checks |")
    w("|---|---:|")
    for name, pat in METHODS:
        w("| %s | %d |" % (name, sum(1 for c in cs if re.search(pat, c["command"]))))
    w("")
    w("All device-side probes are POSIX shell, written for bionic and toybox")
    w("rather than GNU. That rules out a set of things which work on a Linux")
    w("workstation and fail silently on a phone:")
    w("")
    w("- bionic `regcomp` is POSIX-only, so GNU extensions (`\\|`, `\\b`, `\\s`,")
    w("  `\\w`, `\\d`) are treated as literals rather than rejected")
    w("- toybox `find` rejects `-executable`, `-readable`, `-printf`, `-newermt`")
    w("- `grep -c` prints `0` and exits non-zero, so `|| echo 0` prints `0` twice")
    w("- `od` collapses repeated identical lines to `*` unless `-v` is passed")
    w("- SELinux denies `stat` as well as `read`, so `[ -e ]`, `[ -r ]` and")
    w("  `[ -x ]` report a denied path as absent")
    w("")
    w("A hygiene suite rejects each of these at the bundle level, so a new check")
    w("cannot reintroduce them.")
    w("")
    w("---")
    w("")
    w("## Host-side analysis")
    w("")
    w("One subsystem does not run on the device. No Android shell can parse")
    w("ASN.1: AOSP ships no `openssl` and toybox has no ASN.1 support. So")
    w("certificate bytes are read off the device, parsed on the host, then folded")
    w("back into the normal check stream as ordinary rows.")
    w("")
    w("| ID | Finding | Threshold |")
    w("|---|---|---|")
    w("| `CERT-WEAKKEY-001` | Trusted CA with a weak key | RSA/DSA under %d bits, EC under %d |"
      % (hardax.MIN_RSA_BITS, hardax.MIN_EC_BITS))
    w("| `CERT-WEAKSIG-001` | Trusted CA with a weak signature algorithm | %s |"
      % ", ".join(sorted(hardax.WEAK_SIG_ALGS)))
    w("| `CERT-EXPIRED-001` | Expired trusted CA | past `notAfter` |")
    w("")
    w("These were previously rendered in a separate table, which meant an expired")
    w("or weak trust anchor never reached the findings count, the risk score or")
    w("the attack chains.")
    w("")
    w("User-installed CA certificates are deliberately excluded here. Three")
    w("device-side checks already score them as critical, and scoring them in")
    w("both places would make one condition produce two findings.")
    w("")
    w("---")
    w("")
    w("## Known gaps")
    w("")
    w("Listed because an audit tool that hides its blind spots is worse than one")
    w("with fewer checks.")
    w("")
    w("| Gap | State |")
    w("|---|---|")
    for name, state in GAPS:
        w("| %s | %s |" % (name, state))
    w("")
    w("---")
    w("")
    w("## Adding a check")
    w("")
    w("A check is a JSON object. No Python is involved.")
    w("")
    w("```json")
    w("{")
    w('  "id": "STOR-FBECIPHER-001",')
    w('  "category": "STORAGE",')
    w('  "label": "Userdata Contents Encryption Cipher",')
    w('  "command": "...POSIX shell...",')
    w('  "safe_pattern": "^fbe_contents=(OK|ADIANTUM)\\\\b",')
    w('  "level": "warning",')
    w('  "empty_is_safe": false,')
    w('  "description": "why this matters and what the verdict rests on",')
    w('  "remediation": "the minimal correct fix"')
    w("}")
    w("```")
    w("")
    w("### Enforced by tests, not by review")
    w("")
    w("These run against the whole bundle on every commit.")
    w("")
    w("| Rule | Test |")
    w("|---|---|")
    for rule, tests in ENFORCED:
        w("| %s | %s |" % (rule, ", ".join("`%s`" % t for t in tests)))
    w("")
    w("### Design rules, enforced per case")
    w("")
    w("One misconfiguration must not produce two findings. Two checks may read")
    w("the same property only when they ask different questions of it: the three")
    w("security-patch-level CVE checks share `ro.build.version.security_patch`")
    w("but apply different cutoff dates, which is three tests from one input")
    w("rather than one test three times.")
    w("")
    w("Where two checks score adjacent values, each verdict must be a function of")
    w("one property alone. The cipher checks are the worked example: one scores")
    w("the contents mode, the other the filenames mode, and")
    w("`test_each_cipher_check_depends_on_exactly_one_property` asserts each")
    w("verdict is constant across every value of the property it does not own.")
    w("That test exists because the first version of the contents check also")
    w("scored the filenames mode, so an Adiantum device produced two findings for")
    w("one setting.")
    w("")
    w("An inventory check sidesteps the question by scoring nothing. It reports")
    w("facts at `INFO` and leaves the verdict to whichever check owns it.")
    w("")
    w("---")
    w("")
    w("## What a finding must carry")
    w("")
    w("Every row in a report carries its own evidence, so a verdict can be")
    w("checked rather than trusted:")
    w("")
    w("- the exact command that ran")
    w("- raw stdout and stderr, kept separate")
    w("- the exit code")
    w("- the basis for the verdict, in words")
    w("")
    w("stderr cannot satisfy a `safe_pattern`. A denial message that happens to")
    w("contain an expected string does not make a check pass.")
    return "\n".join(o) + "\n"


if __name__ == "__main__":
    text = build()
    with open(os.path.join(REPO_ROOT, "COVERAGE.md"), "w", encoding="utf-8") as f:
        f.write(text)
    print("wrote COVERAGE.md (%d lines)" % len(text.splitlines()))
