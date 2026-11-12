"""COVERAGE.md is generated, so it must match what the generator produces.

The README's category table was hand-maintained and drifted to a total of 816
while the bundle held 855, with 9 of 29 rows stale. COVERAGE.md carries far
more numbers than that table did, so it is generated and pinned rather than
trusted.
"""
import os
import re
import glob
import subprocess
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(REPO_ROOT, "COVERAGE.md")
GEN = os.path.join(REPO_ROOT, "tools", "gen_coverage.py")


def test_generator_ships():
    assert os.path.exists(GEN), "tools/gen_coverage.py is missing"


def test_committed_doc_matches_the_generator():
    """Regenerate and compare. A bundle change without a regeneration fails."""
    sys.path.insert(0, os.path.join(REPO_ROOT, "tools"))
    import importlib.util
    spec = importlib.util.spec_from_file_location("gen_coverage", GEN)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    expected = mod.build()
    actual = open(DOC, encoding="utf-8").read()
    assert actual == expected, (
        "COVERAGE.md is stale. Regenerate it:\n"
        "    python3 tools/gen_coverage.py")


def test_every_cited_test_name_exists():
    """The doc names specific tests as the enforcement mechanism. A name that
    does not exist is an invented citation, which is worse than no citation.
    """
    doc = open(DOC, encoding="utf-8").read()
    cited = set(re.findall(r"`(test_[a-z0-9_]+)`", doc))
    real = set()
    for f in glob.glob(os.path.join(REPO_ROOT, "tests", "*.py")):
        real |= set(re.findall(r"^def (test_[a-z0-9_]+)",
                              open(f, encoding="utf-8").read(), re.M))
    missing = sorted(t for t in cited if t not in real)
    assert not missing, "COVERAGE.md cites tests that do not exist: %s" % missing

    files = set(re.findall(r"`(test_[a-z0-9_]+\.py)`", doc))
    gone = sorted(f for f in files
                  if not os.path.exists(os.path.join(REPO_ROOT, "tests", f)))
    assert not gone, "COVERAGE.md cites test files that do not exist: %s" % gone


def test_example_json_block_matches_a_real_check():
    """The worked example must stay a real check, not drift into fiction."""
    import json
    sys.path.insert(0, os.path.join(REPO_ROOT, "tests"))
    from conftest import load_all_checks
    doc = open(DOC, encoding="utf-8").read()
    blk = re.search(r"```json\n(.*?)```", doc, re.S)
    assert blk, "no JSON example block in COVERAGE.md"
    example = json.loads(blk.group(1))
    real = [c for c in load_all_checks() if c.get("id") == example["id"]]
    assert real, "COVERAGE.md example cites unknown check id %s" % example["id"]
    real = real[0]
    for field in ("label", "safe_pattern", "level", "category"):
        assert example[field] == real[field], (
            "COVERAGE.md example disagrees with the shipping check on %r: "
            "%r vs %r" % (field, example[field], real[field]))


def test_no_em_dashes():
    assert "\u2014" not in open(DOC, encoding="utf-8").read(), \
        "em dash in COVERAGE.md"
