"""Tests for the CLI visual redesign: width-consistency guarantees for every
boxed panel (banner, HUD dashboard) and the boxless category-header rule.

The design review that produced this redesign found real off-by-one width
errors in hand-built mockups and flagged "must use a single pad-to-width
helper with a unit test that asserts every rendered line is exactly the same
character length" as the top implementation risk - these tests exist
specifically to make that guarantee permanent."""
import io
import re
import contextlib

import hardax

_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _visual_width(line):
    return len(_ANSI_RE.sub("", line))


def _box_lines(text):
    """Every line of a captured panel that is part of its box border/body
    (starts with a border character after the leading indent)."""
    return [l for l in text.splitlines() if any(c in l for c in "╭╮╰╯│")]


def test_vtrunc_front_keeps_the_tail():
    assert hardax._vtruncFront("short", 10) == "short"
    long_path = "a/very/long/directory/structure/audit_report.html"
    out = hardax._vtruncFront(long_path, 20)
    assert len(out) == 20
    assert out.startswith("…")
    assert out.endswith("audit_report.html")


def test_vtrunc_front_zero_or_negative_width():
    assert hardax._vtruncFront("anything", 0) == ""
    assert hardax._vtruncFront("anything", -5) == ""


def test_banner_panel_lines_all_have_identical_visual_width():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        hardax.printBanner("SOME-DEVICE-ID", checkCount=767, categoryCount=28)
    out = buf.getvalue()
    lines = _box_lines(out)
    assert len(lines) >= 4, "expected at least top/title/stats/bottom border lines"
    widths = {_visual_width(l) for l in lines}
    assert len(widths) == 1, f"banner lines have inconsistent widths: {widths}"


def test_banner_uses_rounded_corners_not_the_old_mixed_styles():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        hardax.printBanner("D", checkCount=10, categoryCount=2)
    out = buf.getvalue()
    assert "╭" in out and "╮" in out and "╰" in out and "╯" in out
    # the old heavy-box banner style must not reappear
    assert "┏" not in out and "┓" not in out and "┗" not in out and "┛" not in out


def test_banner_has_no_emoji_and_reuses_the_chevron_wordmark():
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        hardax.printBanner("D", checkCount=10, categoryCount=2)
    out = buf.getvalue()
    assert "❯" in out
    assert "📱" not in out and "🔍" not in out


def test_banner_handles_long_device_id_without_overflow():
    # A long SSH/UART idString (e.g. "root@192.168.100.200:22") must not
    # push the box wider than its declared panel width.
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        hardax.printBanner("root@a-very-long-hostname.example.internal:2222",
                           checkCount=767, categoryCount=28)
    widths = {_visual_width(l) for l in _box_lines(buf.getvalue())}
    assert len(widths) == 1


def test_titled_rule_contains_title_and_suffix_and_uses_dash_rule():
    line = hardax._titledRule("BOOT_SECURITY", "(27 checks)")
    plain = _ANSI_RE.sub("", line)
    assert "BOOT_SECURITY" in plain
    assert "(27 checks)" in plain
    assert plain.count("─") > 10
    # boxless: no corner/border characters, this is a category header that
    # repeats ~28 times per run and must never be a box.
    for boxchar in "╭╮╰╯┌┐└┘┏┓┗┛║╔╗╚╝│":
        assert boxchar not in plain


def test_hud_dashboard_boxed_lines_have_identical_visual_width():
    checks = [{"category": f"CAT{i}"} for i in range(5)] * 3
    hud = hardax.HUDDashboard(checks, deviceInfo="TEST-DEVICE")
    lines = [
        hud._lineTopSafe(),
        hud._lineHeaders(),
        hud._lineSepInner(),
        hud._lineCatRow(hud.categoryOrder[0], 0),
        hud._lineBlank(),
        hud._lineSepFull(),
        hud._lineProgress(),
        hud._lineTally(),
        hud._lineBottom(),
    ]
    widths = {_visual_width(l) for l in lines}
    assert len(widths) == 1, f"HUD panel lines have inconsistent widths: {widths}"


def test_hud_dashboard_uses_rounded_corners():
    hud = hardax.HUDDashboard([{"category": "C"}], deviceInfo="D")
    assert "╭" in hud._lineTopSafe() and "╮" in hud._lineTopSafe()
    assert "╰" in hud._lineBottom() and "╯" in hud._lineBottom()
    assert "┌" not in hud._lineTopSafe() and "└" not in hud._lineBottom()


# --- icon-to-count spacing (some terminal fonts render an icon like ⚠ with
# emoji-style double-width presentation, which collides with an immediately
# adjacent digit if there is no gap) ----------------------------------------

def test_hud_tally_has_a_space_between_every_icon_and_its_count():
    hud = hardax.HUDDashboard([{"category": "C"}], deviceInfo="D")
    hud.counts = {"safe": 1, "critical": 2, "warning": 3, "verify": 0, "info": 4, "skipped": 5}
    plain = _ANSI_RE.sub("", hud._lineTally())
    for icon in ("✓", "✗", "⚠", "⊘", "ℹ"):
        idx = plain.index(icon)
        assert plain[idx + 1] == " ", f"no space after {icon!r} in HUD tally: {plain!r}"


# --- terminal-width-aware line fitting (--show-commands mode) --------------
#
# The "-> Trying: <candidate command>" line previously had NO length cap at
# all, and the "$ command" / "Fix: remediation" lines used fixed 60/70-char
# budgets that could still overflow an 80-column terminal. _fitLine() bounds
# all three to the REAL terminal width so nothing ever needs horizontal
# scrolling, with a graceful fallback when the width can't be detected.

def test_fitline_bounds_to_a_narrow_terminal(monkeypatch):
    long_cmd = "su -c '" + ("x" * 200) + "'"
    monkeypatch.setattr(hardax.Terminal, "getSize", staticmethod(lambda: (60, 24)))
    prefix = len("  -> Trying: ")
    fitted = hardax._fitLine(prefix, long_cmd)
    assert prefix + len(fitted) <= 60
    assert fitted.endswith("…")


def test_fitline_passes_short_commands_through_unchanged_on_a_wide_terminal(monkeypatch):
    short_cmd = "getprop ro.boot.veritymode"
    monkeypatch.setattr(hardax.Terminal, "getSize", staticmethod(lambda: (160, 24)))
    prefix = len("  -> Trying: ")
    assert hardax._fitLine(prefix, short_cmd) == short_cmd


def test_fitline_never_goes_below_minlen_on_an_extremely_narrow_terminal(monkeypatch):
    monkeypatch.setattr(hardax.Terminal, "getSize", staticmethod(lambda: (10, 24)))
    fitted = hardax._fitLine(13, "some long command text here", minLen=20)
    assert len(fitted) == 20
