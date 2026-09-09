"""The human-readable reports must show what a verdict was taken from.

Before this, every writer except JSON printed a bare `Status: CRITICAL` with
no indication of how it was decided. The engine had recorded the deciding
observation and the raw streams on every row since v6.2.0, and all four
human formats discarded it. That is what let a SAFE built on empty output
read exactly like a SAFE built on a command that ran and returned a clean
answer.
"""

import io
import contextlib

import pytest

import hardax
from conftest import FakeDevice


CHECKS = [
    # measured and failed: evidence is the returned output
    {"category": "PARTITION", "label": "overlay-check", "level": "critical",
     "description": "d", "remediation": "fix it",
     "command": "cat /proc/mounts", "safe_pattern": r"^firmware_overlays=0\b"},
    # scored SAFE purely because nothing came back
    {"category": "MALWARE", "label": "rat-check", "level": "critical",
     "description": "d", "remediation": "fix it",
     "command": "ps -A | grep rat", "safe_pattern": "^$", "empty_is_safe": True},
    # denied read: the denial itself is the evidence
    {"category": "SYSTEM", "label": "sysctl-check", "level": "warning",
     "description": "d", "remediation": "fix it",
     "command": "cat /proc/sys/kernel/modules_disabled", "safe_pattern": "^1$"},
]

ANSWERS = {
    "cat /proc/mounts": ("firmware_overlays=2 firmware_paths=[/system]", "", 0),
    "ps -A | grep rat": ("", "", 1),
    "cat /proc/sys/kernel/modules_disabled":
        ("", "cat: /proc/sys/kernel/modules_disabled: Permission denied", 1),
}


class _Device(hardax.Device):
    def shellEx(self, command):
        return hardax.ShellResult(*ANSWERS.get(command, ("", "", 0)))

    def shell(self, command):
        return self.shellEx(command).merged

    def idString(self):
        return "report-evidence-device"


@pytest.fixture(scope="module")
def scanned():
    with contextlib.redirect_stdout(io.StringIO()):
        rows, counts = hardax.runChecks(_Device(), CHECKS)
    return rows, counts


def test_every_row_still_carries_its_evidence(scanned):
    rows, _ = scanned
    for row in rows:
        ev = row["evidence"]
        assert ev["basis"], row["label"]
        assert "exit_code" in ev


def test_txt_report_shows_basis_and_device_output(scanned, tmp_path):
    rows, counts = scanned
    p = tmp_path / "r.txt"
    hardax.writeTxtReport(str(p), {"model": "m"}, rows, counts, None, "dev")
    text = p.read_text(encoding="utf-8")

    assert "Basis: stdout did not match safe_pattern" in text
    assert "firmware_overlays=2 firmware_paths=[/system]" in text
    # a SAFE built on silence must say so rather than look like a real pass
    assert "Device output: (none)" in text
    # a denial must reach the reader verbatim
    assert "Permission denied" in text
    assert "Exit code: 1" in text


def test_xlsx_findings_sheet_has_evidence_columns(scanned, tmp_path):
    openpyxl = pytest.importorskip("openpyxl")
    rows, counts = scanned
    p = tmp_path / "r.xlsx"
    hardax.writeXlsxReport(str(p), {"model": "m"}, rows, counts, None, "dev")

    ws = openpyxl.load_workbook(str(p))["Findings"]
    header = [c.value for c in ws[1]]
    for col in ("Basis", "Device stdout", "Device stderr", "Exit code"):
        assert col in header, header
    # Status must stay in column 4: the status fill is written positionally
    assert header[3] == "Status"

    idx = {h: n for n, h in enumerate(header, 1)}
    body = [[ws.cell(r, c).value for c in range(1, len(header) + 1)]
            for r in range(2, ws.max_row + 1)]
    bases = [r[idx["Basis"] - 1] for r in body]
    assert any("did not match safe_pattern" in (b or "") for b in bases)
    assert any("Permission denied" in (r[idx["Device stderr"] - 1] or "")
               for r in body)


def test_html_report_shows_basis_and_streams(scanned, tmp_path):
    rows, counts = scanned
    p = tmp_path / "r.html"
    hardax.writeHtmlReport(str(p), {"model": "m"}, rows, counts, None)
    html = p.read_text(encoding="utf-8")

    assert html.count('detail-tag">Basis') == len(rows)
    assert "Device stdout" in html
    assert "Device stderr" in html
    assert "Permission denied" in html
    # the empty-output SAFE must not silently render as a blank block
    assert "(none)" in html


def test_json_report_still_carries_the_full_record(scanned, tmp_path):
    import json
    rows, counts = scanned
    p = tmp_path / "r.json"
    hardax.writeJsonReport(str(p), {"model": "m"}, rows, counts, None, "dev")
    payload = json.loads(p.read_text(encoding="utf-8"))
    for check in payload["checks"]:
        assert "evidence" in check and check["evidence"]["basis"]
