"""Smoke tests for the report writers: they must produce well-formed output
for TXT, CSV, JSON and HTML without raising."""
import json

import hardax
from hardax import analysis


def _rows():
    return [{
        "timestamp": "2026-01-01 00:00:00", "category": "SYSTEM", "label": "A Check",
        "level": "critical", "bucket": "critical", "status": "CRITICAL",
        "matched": "False", "command": "getprop x", "result": "bad value",
        "description": "desc", "needs_verification": False, "baseline": "",
        "remediation": "fix it",
    }]


def _counts():
    return {"safe": 0, "warning": 0, "critical": 1, "info": 0, "verify": 0, "skipped": 0}


def _device():
    return {"model": "M", "brand": "B", "manufacturer": "Mf", "name": "N",
            "soc_manufacturer": "S", "soc_model": "SM", "android_version": "14",
            "sdk_level": "34", "build_id": "b", "fingerprint": "fp", "serialno": "sn",
            "timezone": "UTC"}


def test_csv_report_includes_baseline_column(tmp_path):
    p = str(tmp_path / "r.csv")
    hardax.writeCsvReport(p, _rows())
    content = open(p, encoding="utf-8").read()
    assert "baseline" in content.splitlines()[0]  # header
    assert "CRITICAL" in content


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
