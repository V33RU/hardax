"""Smoke tests for the report writers: they must produce well-formed output
for TXT, CSV, JSON and HTML without raising."""
import json

import pytest

import hardax
from hardax import analysis


def _rows():
    return [{
        "timestamp": "2026-01-01 00:00:00", "category": "SYSTEM", "id": "SYS-1",
        "label": "A Check", "level": "critical", "severity": "", "bucket": "critical",
        "status": "CRITICAL", "matched": "False", "command": "getprop x",
        "result": "bad value", "description": "desc",
        "why": "matters because reasons", "risk_if_fail": "bad things happen",
        "expected_secure_state": "should be safe", "nist_800_53": "AC-3",
        "cis_id": "1.3", "tags": ["kernel", "selinux"],
        "needs_verification": False, "baseline": "", "remediation": "fix it",
    }]


def _counts():
    return {"safe": 0, "warning": 0, "critical": 1, "info": 0, "verify": 0, "skipped": 0}


def _device():
    return {"model": "M", "brand": "B", "manufacturer": "Mf", "name": "N",
            "soc_manufacturer": "S", "soc_model": "SM", "android_version": "14",
            "sdk_level": "34", "build_id": "b", "fingerprint": "fp", "serialno": "sn",
            "timezone": "UTC"}


def test_csv_report_includes_technical_columns(tmp_path):
    p = str(tmp_path / "r.csv")
    hardax.writeCsvReport(p, _rows())
    content = open(p, encoding="utf-8").read()
    header = content.splitlines()[0]
    for col in ("baseline", "why", "risk_if_fail", "expected_secure_state",
                "nist_800_53", "cis_id", "tags"):
        assert col in header, col
    assert "CRITICAL" in content
    assert "kernel, selinux" in content  # list tags are joined for CSV


def test_xlsx_report_sheets_and_technical_columns(tmp_path):
    openpyxl = pytest.importorskip("openpyxl")
    from hardax import analysis
    p = str(tmp_path / "r.xlsx")
    a = analysis.analyze_findings(_rows(), _counts(), profile="pos")
    hardax.writeXlsxReport(p, _device(), _rows(), _counts(), [], "target", a)
    wb = openpyxl.load_workbook(p)
    assert {"Summary", "Findings", "Analysis"}.issubset(set(wb.sheetnames))
    hdr = [c.value for c in wb["Findings"][1]]
    for col in ("Category", "Status", "Why it matters", "Risk if failed",
                "Expected secure state", "Command", "Remediation", "NIST 800-53"):
        assert col in hdr, col
    why_col = hdr.index("Why it matters") + 1
    assert "matters because" in str(wb["Findings"].cell(2, why_col).value)


def test_csv_report_truncates_unbounded_result_field(tmp_path):
    # A misbehaving check (or a shell operator-precedence bug) can return
    # megabytes of raw output. The CSV writer must cap it so the cell never
    # exceeds Excel's 32,767-char limit or breaks csv.reader's default
    # field_size_limit (131072) for downstream tooling.
    rows = _rows()
    rows[0]["result"] = "A" * 500_000
    p = str(tmp_path / "r.csv")
    hardax.writeCsvReport(p, rows)
    import csv as csvmod
    with open(p, encoding="utf-8", newline="") as f:
        parsed = list(csvmod.reader(f))  # must not raise with the default field_size_limit
    assert len(parsed) == 2
    result_cell = parsed[1][parsed[0].index("result")]
    assert len(result_cell) < 32767
    assert "truncated, 500000 chars total" in result_cell
    assert "--json-out" in result_cell


def test_xlsx_report_handles_list_valued_compliance_fields(tmp_path):
    # nist_800_53 / cis_id can be multi-valued in check JSON; the writer must
    # coerce them instead of letting openpyxl raise and abort the audit.
    openpyxl = pytest.importorskip("openpyxl")
    rows = _rows()
    rows[0]["nist_800_53"] = ["AC-3", "SC-7"]
    rows[0]["cis_id"] = ["1.1", "1.2"]
    p = str(tmp_path / "r.xlsx")
    hardax.writeXlsxReport(p, _device(), rows, _counts(), [], "target", None)  # must not raise
    wb = openpyxl.load_workbook(p)
    hdr = [c.value for c in wb["Findings"][1]]
    nist_col = hdr.index("NIST 800-53") + 1
    assert "AC-3" in str(wb["Findings"].cell(2, nist_col).value)


def test_json_report_is_valid_and_complete(tmp_path):
    p = str(tmp_path / "r.json")
    hardax.writeJsonReport(p, _device(), _rows(), _counts(), [], "target", None)
    d = json.load(open(p, encoding="utf-8"))
    assert d["version"] == hardax.__version__
    assert d["counts"]["critical"] == 1
    assert d["checks"][0]["status"] == "CRITICAL"
    assert d["target"] == "target"


def test_json_report_embeds_analysis(tmp_path):
    p = str(tmp_path / "r.json")
    a = analysis.analyze_findings(_rows(), _counts(), profile="pos")
    hardax.writeJsonReport(p, _device(), _rows(), _counts(), [], "target", a)
    d = json.load(open(p, encoding="utf-8"))
    assert d["analysis"]["profile"] == "pos"
    assert "risk_score" in d["analysis"]


def test_txt_report_renders(tmp_path):
    p = str(tmp_path / "r.txt")
    hardax.writeTxtReport(p, _device(), _rows(), _counts(), [], "target", None)
    text = open(p, encoding="utf-8").read()
    assert "AUDIT SUMMARY" in text
    assert "A Check" in text


def test_html_report_renders(tmp_path):
    p = str(tmp_path / "r.html")
    hardax.writeHtmlReport(p, _device(), _rows(), _counts(), [], None)
    html = open(p, encoding="utf-8").read()
    assert "<" in html and "A Check" in html
