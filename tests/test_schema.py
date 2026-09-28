"""Validate the bundled command files against the shipped JSON schema, and
enforce cross-file invariants the schema cannot express (regex validity,
unique ids, doc-count consistency)."""
import os
import re
import json
import glob
from collections import Counter

import pytest
from jsonschema import Draft7Validator

from conftest import COMMANDS_DIR, SCHEMA_PATH, REPO_ROOT, load_all_checks


def _schema():
    return json.load(open(SCHEMA_PATH, encoding="utf-8"))


def test_schema_file_ships_and_is_valid_draft7():
    assert os.path.isfile(SCHEMA_PATH), "commands.schema.json must ship in the package"
    Draft7Validator.check_schema(_schema())


def test_every_command_file_matches_schema():
    validator = Draft7Validator(_schema())
    errors = []
    for fp in sorted(glob.glob(os.path.join(COMMANDS_DIR, "*.json"))):
        data = json.load(open(fp, encoding="utf-8"))
        for err in validator.iter_errors(data):
            errors.append(f"{os.path.basename(fp)}: {list(err.path)}: {err.message}")
    assert not errors, "schema violations:\n" + "\n".join(errors)


def test_all_safe_patterns_compile():
    bad = []
    for c in load_all_checks():
        try:
            re.compile(c["safe_pattern"], re.IGNORECASE | re.MULTILINE | re.DOTALL)
        except re.error as e:
            bad.append(f"{c['_file']} [{c['label']}]: {e}")
    assert not bad, "invalid safe_pattern regex:\n" + "\n".join(bad)


def test_ids_are_unique_across_all_files():
    ids = [(c["id"], c["_file"]) for c in load_all_checks() if c.get("id")]
    counts = Counter(i for i, _ in ids)
    dups = {i: n for i, n in counts.items() if n > 1}
    assert not dups, f"duplicate check ids: {dups}"


def test_categories_and_files_are_consistent():
    checks = load_all_checks()
    assert len(checks) > 700, "unexpectedly few checks"
    # Every check has a non-empty category.
    assert all(c.get("category") for c in checks)


def test_readme_badge_counts_match_reality():
    """Guards against doc drift: the README badges must match the real counts."""
    readme = os.path.join(REPO_ROOT, "README.md")
    if not os.path.isfile(readme):
        pytest.skip("README not present (installed context)")
    text = open(readme, encoding="utf-8").read()
    checks = load_all_checks()
    n_checks = len(checks)
    n_cats = len({c["category"] for c in checks})

    m = re.search(r"badge/checks-(\d+)", text)
    assert m and int(m.group(1)) == n_checks, (
        f"README checks badge {m.group(1) if m else '?'} != actual {n_checks}")
    m = re.search(r"badge/categories-(\d+)", text)
    assert m and int(m.group(1)) == n_cats, (
        f"README categories badge {m.group(1) if m else '?'} != actual {n_cats}")


def test_readme_prose_check_counts_match_reality():
    """The badge was enforced but the prose was not, so the README shipped
    "816 security checks" to PyPI while the badge and the actual bundle said
    826. Every number in the README that claims a check count is pinned here.
    """
    import re, os
    from conftest import load_all_checks
    n = len(load_all_checks())
    readme = os.path.join(REPO_ROOT, "README.md")
    text = open(readme, encoding="utf-8").read()
    claims = re.findall(r"(\d{3,4})\s+(?:[Ss]ecurity\s+)?[Cc]hecks", text)
    wrong = sorted({c for c in claims if int(c) != n})
    assert not wrong, (
        "README claims %s check(s) but the bundle has %d: %s"
        % ("/".join(wrong), n, readme))


def test_labels_are_unique_across_all_files():
    """Two checks sharing a label are indistinguishable in every report, in the
    XLSX filter and in any diff between runs, and the analysis engine keys
    attack-chain membership on the label. Ids were already pinned; labels were
    not."""
    import collections
    seen = collections.Counter(c["label"] for c in load_all_checks())
    dups = {l: n for l, n in seen.items() if n > 1}
    assert not dups, "duplicate check labels: %s" % dups


def test_no_two_checks_scan_the_same_name_set():
    """Guard against re-adding a binary-presence check that duplicates an
    existing one. Two checks may legitimately share a path list, but not a path
    list AND the same `grep -E` name alternation."""
    import re as _re
    seen = {}
    dups = []
    for c in load_all_checks():
        m = _re.search(r"for d in ([^;]+); do.*?grep -E '([^']+)'", c["command"], _re.S)
        if not m:
            continue
        key = (m.group(1).strip(), m.group(2))
        if key in seen:
            dups.append("%s duplicates %s" % (c["label"], seen[key]))
        seen[key] = c["label"]
    assert not dups, "checks scanning an identical path+name set:\n  " + "\n  ".join(dups)
