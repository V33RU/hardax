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
