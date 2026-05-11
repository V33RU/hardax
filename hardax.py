#!/usr/bin/env python3
"""
HARDAX - Hardening Audit eXaminer
Android OS based Connected Devices Security Configuration Auditor

Android OS based Connected Devices Security Configuration Auditor | 3 Report Formats
Author : Mr-IoT (IOTSRG)
License: MIT
"""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  IMPORTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import argparse
import getpass
import base64
import collections
import csv
import html
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import time
from datetime import datetime
from string import Template
from typing import List, Dict, Any, Tuple, Optional

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  PYTHON VERSION CHECK
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if sys.version_info < (3, 11):
    sys.exit(f"[ERROR] HARDAX requires Python 3.11 or higher. "
             f"Detected: {sys.version_info.major}.{sys.version_info.minor}")

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  VERSION & CONSTANTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

__version__ = "5.1.0"

REQUIRED_CHECK_KEYS = {"category", "label", "command", "safe_pattern", "level", "description"}

ADB_TRANSPORT_ERRORS = [
    "device offline",
    "device not found",
    "device unauthorized",
    "no devices/emulators found",
    "no devices found",
    "closed",
    "protocol fault",
    "device still authorizing",
    "insufficient permissions",
    "more than one device",
    "adb: error:",
]

# Maximum output length to consider as a transport/service error
_ADB_ERROR_MAX_LEN = 300
_SVC_ERROR_MAX_LEN = 150

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLI ARGV SHIM - strip extra flags before argparse
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

try:
    _cleanArgv = [sys.argv[0]]
    _idx = 1
    while _idx < len(sys.argv):
        flag = sys.argv[_idx]
        if flag == "--net-debug":
            os.environ["HARDAX_NET_DEBUG"] = "1"
        elif flag == "--net-strict":
            os.environ["HARDAX_NET_STRICT"] = "1"
        elif flag == "--cert-debug":
            os.environ["HARDAX_CERT_DEBUG"] = "1"
        elif flag == "--cert-limit":
            if _idx + 1 < len(sys.argv):
                os.environ["HARDAX_CERT_LIMIT"] = sys.argv[_idx + 1]
                _idx += 1
        else:
            _cleanArgv.append(flag)
        _idx += 1
    sys.argv = _cleanArgv
except Exception:
    pass

NET_DEBUG = bool(os.environ.get("HARDAX_NET_DEBUG"))
NET_STRICT = bool(os.environ.get("HARDAX_NET_STRICT"))
CERT_DEBUG = bool(os.environ.get("HARDAX_CERT_DEBUG"))

try:
    CERT_LIMIT = int(os.environ.get("HARDAX_CERT_LIMIT", "50"))
except Exception:
    CERT_LIMIT = 50


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  TERMINAL COLORS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class Colors:
    """ANSI escape codes for terminal output."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"


def supportsColor() -> bool:
    """Check whether the terminal supports ANSI colour sequences."""
    if not hasattr(sys.stdout, "isatty"):
        return False
    if not sys.stdout.isatty():
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return True


if not supportsColor():
    for attr in dir(Colors):
        if not attr.startswith("_"):
            setattr(Colors, attr, "")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  TERMINAL HELPERS (pure ANSI, no curses)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class Terminal:
    """Low-level terminal cursor / screen helpers using ANSI escape codes."""

    @staticmethod
    def hideCursor():
        sys.stdout.write("\033[?25l")
        sys.stdout.flush()

    @staticmethod
    def showCursor():
        sys.stdout.write("\033[?25h")
        sys.stdout.flush()

    @staticmethod
    def cursorUp(n: int):
        if n > 0:
            sys.stdout.write(f"\033[{n}A")

    @staticmethod
    def clearLine():
        sys.stdout.write("\033[2K\r")

    @staticmethod
    def getSize() -> Tuple[int, int]:
        """Return (columns, rows) of the terminal."""
        sz = shutil.get_terminal_size(fallback=(80, 24))
        return sz.columns, sz.lines


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  HUD TACTICAL DASHBOARD
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Regex to strip ANSI escape codes for visual-width calculations
_ANSI_RE = re.compile(r'\033\[[0-9;]*m')


def _vlen(s: str) -> int:
    """Visual length of a string, ignoring ANSI escape codes."""
    return len(_ANSI_RE.sub('', s))


def _vpad(s: str, width: int) -> str:
    """Right-pad a string with spaces to reach a target *visual* width."""
    diff = width - _vlen(s)
    return s + (' ' * diff) if diff > 0 else s


def _vtrunc(s: str, maxLen: int) -> str:
    """Truncate a plain string to maxLen visual chars, adding … if needed."""
    if maxLen <= 0:
        return ""
    if len(s) <= maxLen:
        return s
    return s[:maxLen - 1] + "…"


class HUDDashboard:
    """Live split-panel HUD with categories on left, findings feed on right.

    Every line is built by:
      1. composing *plain text* segments first (known visual widths)
      2. wrapping with ANSI colour
      3. using _vpad() to pad to the exact column before adding borders

    This guarantees the right-hand │ always aligns.
    """

    _STATUS_FMT = {
        "SAFE":     (Colors.GREEN,          "✓"),
        "CRITICAL": (Colors.BRIGHT_RED,     "✗"),
        "WARNING":  (Colors.YELLOW,         "⚠"),
        "VERIFY":   (Colors.BRIGHT_MAGENTA, "?"),
        "INFO":     (Colors.CYAN,           "ℹ"),
        "SKIPPED":  (Colors.DIM,            "⊘"),
    }

    # Fixed layout constants  (inner widths, excluding the border chars)
    LW = 34        # left-panel visual width (between │…│)
    RW = 36        # right-panel visual width (between │…│)
    # Total inner = LW + 1(sep│) + RW = 71   + 2 outer │ = 73 visual
    # With 2-space indent: 75 chars per line - fits 80-col terminals.

    def __init__(self, checks: List[Dict[str, Any]], deviceInfo: str = ""):
        seen: Dict[str, int] = {}
        for chk in checks:
            cat = chk.get("category", "General")
            seen[cat] = seen.get(cat, 0) + 1

        self.categoryOrder = list(seen.keys())
        self.categoryTotals = seen
        self.categoryDone = {c: 0 for c in self.categoryOrder}
        self.activeCategory = self.categoryOrder[0] if self.categoryOrder else ""
        self.totalChecks = len(checks)
        self.totalDone = 0
        self.deviceInfo = deviceInfo
        self.startTime = time.time()

        self._maxFindings = len(self.categoryOrder)
        self.findings: collections.deque = collections.deque(maxlen=self._maxFindings)

        self.counts = {"safe": 0, "critical": 0, "warning": 0,
                        "verify": 0, "info": 0, "skipped": 0}

        # Panel height = header(3) + cat rows + blankrow(1) + sep(1) + progress(1) + tally(1) + bottom(1) = cats+8
        self._catRows = len(self.categoryOrder)
        self.panelHeight = self._catRows + 8

        W = self.LW + 1 + self.RW  # full inner width (between outer │ │)
        self._W = W

        Terminal.hideCursor()
        self._render(first=True)

    # ── helpers ────────────────────────────────────────────

    @staticmethod
    def _bar(done: int, total: int, width: int = 20) -> str:
        """█░ progress bar with colour gradient, exact *width* visual chars."""
        if total == 0:
            return Colors.DIM + "░" * width + Colors.RESET
        frac = min(done / total, 1.0)
        filled = int(frac * width)
        col = Colors.BRIGHT_RED if frac < 0.33 else Colors.YELLOW if frac < 0.66 else Colors.GREEN
        return col + "█" * filled + Colors.DIM + "░" * (width - filled) + Colors.RESET

    def _eta(self) -> str:
        if self.totalDone == 0:
            return "--:--"
        elapsed = time.time() - self.startTime
        remaining = int((elapsed / self.totalDone) * (self.totalChecks - self.totalDone))
        return f"{remaining // 60}m{remaining % 60:02d}s" if remaining >= 60 else f"{remaining}s"

    # ── line builders (each returns a string with ANSI, exact visual width) ──

    def _lineTopSafe(self) -> str:
        """Top border built with guaranteed alignment."""
        D = Colors.DIM; R = Colors.RESET; B = Colors.BOLD
        W = Colors.BRIGHT_WHITE; C = Colors.BRIGHT_CYAN; Y = Colors.YELLOW
        dev = _vtrunc(self.deviceInfo, 20) if self.deviceInfo else ""
        # plain text (no colour) to measure
        plain = f"─── HARDAX v{__version__} ── {dev} ── {self.totalChecks} checks "
        fill = max(1, self._W - len(plain))
        coloured = (f"{D}───{R} {B}{W}HARDAX v{__version__}{R} "
                    f"{D}──{R} {C}{dev}{R} "
                    f"{D}──{R} {Y}{self.totalChecks} checks{R} "
                    f"{D}{'─' * fill}{R}")
        return f"  {D}┌{R}{coloured}{D}┐{R}"

    def _lineHeaders(self) -> str:
        D = Colors.DIM; R = Colors.RESET; B = Colors.BOLD; W = Colors.BRIGHT_WHITE
        left = _vpad(f" {B}{W}CATEGORIES{R}", self.LW)
        right = _vpad(f"{B}{W}LIVE FINDINGS{R}", self.RW)
        return f"  {D}│{R}{left}{D}│{R}{right}{D}│{R}"

    def _lineSepInner(self) -> str:
        """Sub-header separator: │ ─────────│─────────│"""
        D = Colors.DIM; R = Colors.RESET
        return f"  {D}│{'─' * self.LW}│{'─' * self.RW}│{R}"

    def _lineCatRow(self, cat: str, findIdx: int) -> str:
        """One category row with left + right panels."""
        D = Colors.DIM; R = Colors.RESET; B = Colors.BOLD
        W = Colors.BRIGHT_WHITE; G = Colors.GREEN; C = Colors.BRIGHT_CYAN
        done = self.categoryDone.get(cat, 0)
        total = self.categoryTotals.get(cat, 0)

        # Icon (1 visual char)
        if done >= total > 0:
            icon = f"{G}✓{R}"
        elif cat == self.activeCategory and done > 0:
            icon = f"{C}◈{R}"
        elif cat == self.activeCategory:
            icon = f"{C}▶{R}"
        else:
            icon = f"{D}·{R}"

        # Name (16 visual chars)
        name16 = _vtrunc(cat, 16)
        if cat == self.activeCategory:
            nameC = f"{B}{W}{name16}{R}"
        elif done >= total > 0:
            nameC = f"{G}{name16}{R}"
        else:
            nameC = f"{D}{name16}{R}"
        nameC = _vpad(nameC, 16)

        # Count: "  4/84 " (7 visual)
        countPlain = f"{done:>3}/{total}"
        countC = f"{W}{countPlain}{R}" if done > 0 else f"{D}{countPlain}{R}"

        # Pct: "100%" or " --" (4 visual)
        if total > 0 and done > 0:
            pctPlain = f"{done * 100 // total:3d}%"
        else:
            pctPlain = "  --"
        pctC = f"{D}{pctPlain}{R}"

        # left: icon(1) + sp(1) + name(16) + sp(1) + count(~7) + sp(1) + pct(4) + sp(~3)
        # Total left visual = 1+1+16+1+7+1+4 = 31, pad to LW
        leftContent = f"{icon} {nameC} {countC} {pctC}"
        left = _vpad(leftContent, self.LW)

        # Right panel: finding
        right = self._findingCell(findIdx)

        return f"  {D}│{R}{left}{D}│{R}{right}{D}│{R}"

    def _findingCell(self, idx: int) -> str:
        """Build right-panel cell for findings row idx, padded to RW."""
        R = Colors.RESET; D = Colors.DIM
        if idx < len(self.findings):
            status, label = self.findings[idx]
            col, _ = self._STATUS_FMT.get(status, (D, "·"))
            tag = status[:4]
            lbl = _vtrunc(label, self.RW - 8)
            cell = f"{col}[{tag}]{R} {lbl}"
        else:
            cell = ""
        return _vpad(cell, self.RW)

    def _lineBlank(self) -> str:
        D = Colors.DIM; R = Colors.RESET
        return f"  {D}│{' ' * self.LW}│{' ' * self.RW}│{R}"

    def _lineSepFull(self) -> str:
        """Separator: ├──────┴──────┤"""
        D = Colors.DIM; R = Colors.RESET
        return f"  {D}├{'─' * self.LW}┴{'─' * self.RW}┤{R}"

    def _lineProgress(self) -> str:
        D = Colors.DIM; R = Colors.RESET; W = Colors.BRIGHT_WHITE
        barW = 20
        bar = self._bar(self.totalDone, self.totalChecks, barW)
        pct = (self.totalDone / self.totalChecks * 100) if self.totalChecks else 0
        # plain: "  " + bar(20) + "  " + "NNN/NNN" + "  " + "PPP.P%" + "    ETA XXmXXs"
        countPlain = f"{self.totalDone:>3}/{self.totalChecks}"
        pctPlain = f"{pct:5.1f}%"
        etaPlain = f"ETA {self._eta()}"
        content = f" {bar}  {W}{countPlain}{R}  {D}{pctPlain}{R}    {D}{etaPlain}{R}"
        return f"  {D}│{R}{_vpad(content, self._W)}{D}│{R}"

    def _lineTally(self) -> str:
        D = Colors.DIM; R = Colors.RESET
        G = Colors.GREEN; RD = Colors.BRIGHT_RED; Y = Colors.YELLOW; C = Colors.CYAN
        c = self.counts
        tally = (f" {G}✓{c['safe']}{R} SAFE  "
                 f"{RD}✗{c['critical']}{R} CRIT  "
                 f"{Y}⚠{c['warning']}{R} WARN  "
                 f"{D}⊘{c['skipped']}{R} SKIP  "
                 f"{C}ℹ{c['info']}{R} INFO")
        return f"  {D}│{R}{_vpad(tally, self._W)}{D}│{R}"

    def _lineBottom(self) -> str:
        D = Colors.DIM; R = Colors.RESET
        return f"  {D}└{'─' * self._W}┘{R}"

    # ── full frame ──────────────────────────────────────────

    def _buildFrame(self) -> str:
        lines = [
            self._lineTopSafe(),
            self._lineHeaders(),
            self._lineSepInner(),
        ]
        for i, cat in enumerate(self.categoryOrder):
            lines.append(self._lineCatRow(cat, i))
        lines.append(self._lineBlank())
        lines.append(self._lineSepFull())
        lines.append(self._lineProgress())
        lines.append(self._lineTally())
        lines.append(self._lineBottom())
        return "\n".join(lines)

    def _render(self, first: bool = False):
        if first:
            sys.stdout.write("\033[s")   # save cursor position before first draw
        else:
            sys.stdout.write("\033[u")   # restore to saved position before redraw
        print(self._buildFrame())
        sys.stdout.flush()

    # ── public API ──────────────────────────────────────────

    def onCheckComplete(self, category: str, label: str, status: str):
        """Called after each check completes. Updates stats and redraws."""
        self.activeCategory = category
        self.categoryDone[category] = self.categoryDone.get(category, 0) + 1
        self.totalDone += 1

        bucket = status.lower()
        if bucket in self.counts:
            self.counts[bucket] += 1

        if status not in ("SAFE", "INFO"):
            self.findings.append((status, label))

        self._render()

    def finish(self):
        """Restore cursor and print completion message."""
        Terminal.showCursor()
        elapsed = time.time() - self.startTime
        mins = int(elapsed) // 60
        secs = int(elapsed) % 60
        print(f"\n  {Colors.GREEN}✓{Colors.RESET} {Colors.BOLD}Audit complete{Colors.RESET} in {mins}m{secs:02d}s\n")


# Global dashboard reference for signal handler
_active_dashboard: Optional['HUDDashboard'] = None


def _signalHandler(signum, frame):
    """Restore terminal on Ctrl+C."""
    Terminal.showCursor()
    print(f"\n\n  {Colors.YELLOW}⚠ Audit interrupted by user (Ctrl+C){Colors.RESET}\n")
    sys.exit(130)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  GENERAL UTILITIES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def which(prog: str) -> Optional[str]:
    return shutil.which(prog)


def runLocal(cmd: List[str], timeout: Optional[int] = None) -> Tuple[int, str, str]:
    """Execute a local subprocess and return (returncode, stdout, stderr)."""
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        out, err = proc.communicate(timeout=timeout)
        return proc.returncode, out, err
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.communicate()
        return -1, "", "timeout"


def htmlEscape(s: str) -> str:
    return html.escape(s, quote=True)


def normalizeForMatch(s: str) -> str:
    """Normalize line endings while preserving newlines for multi-line regex."""
    return (s or "").replace("\r\n", "\n").replace("\r", "\n")


def bucketFromLevel(level: str) -> str:
    """Map granular severity labels to the three evaluation buckets."""
    lvl = (level or "").strip().lower()
    if lvl in ("critical", "high"):
        return "critical"
    if lvl in ("warning", "medium"):
        return "warning"
    return "info"


SERVICE_ERRORS = [
    "can't find service",
    "service not found",
    "failed to find service",
    "does not exist",
    "cmd: can't find",
]


def isServiceError(output: str) -> bool:
    """Return True when *output* indicates a missing Android service."""
    if not output:
        return False
    lower = output.lower().strip()
    for indicator in SERVICE_ERRORS:
        if indicator in lower and len(lower) < _SVC_ERROR_MAX_LEN:
            return True
    return False


def isAdbTransportError(output: str) -> bool:
    """Return True when *output* looks like an ADB transport / connection error."""
    if not output:
        return False
    lower = output.lower().strip()
    if len(lower) > _ADB_ERROR_MAX_LEN:
        return False
    return any(sig in lower for sig in ADB_TRANSPORT_ERRORS)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ADB HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def listAdbDevices() -> list:
    code, out, _ = runLocal(["adb", "devices", "-l"])
    if code != 0:
        return []
    lines = [ln.strip() for ln in out.splitlines()[1:] if ln.strip()]
    devices = []
    for ln in lines:
        parts = ln.split()
        if not parts:
            continue
        serial = parts[0]
        state = parts[1] if len(parts) > 1 else "unknown"
        desc = " ".join(parts[2:]) if len(parts) > 2 else ""
        devices.append({"serial": serial, "state": state, "desc": desc})
    return devices


def pickDefaultSerial(userSerial: Optional[str]) -> Optional[str]:
    if userSerial:
        return userSerial
    devs = listAdbDevices()
    healthy = [d for d in devs if d["state"] == "device"]
    if len(healthy) == 1:
        return healthy[0]["serial"]
    return None


def explainAdbDevicesAndExit(exitCode: int = 2):
    devs = listAdbDevices()
    if not devs:
        msg = (
            "No ADB devices detected.\n\n"
            "Troubleshooting:\n"
            "   Enable Developer options and USB debugging on the device\n"
            "   Trust this computer on the device prompt\n"
            "   Run: adb kill-server && adb start-server\n"
            "   Check USB cable/port or try: adb tcpip 5555; adb connect <ip>:5555\n"
        )
        print(msg, file=sys.stderr)
        sys.exit(exitCode)
    lines = ["Detected ADB endpoints (use --serial <id>):"]
    for d in devs:
        lines.append(f"  - {d['serial']:>24}   {d['state']:<12}   {d['desc']}")
    lines.append("\nNotes:")
    lines.append("   Only devices in state 'device' are usable.")
    lines.append("   If you see 'unauthorized', unlock the phone and accept the RSA fingerprint dialog.")
    lines.append("   If multiple 'device' entries exist, pass --serial <id>.")
    print("\n".join(lines), file=sys.stderr)
    sys.exit(exitCode)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  DEVICE INTERFACES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class Device:
    """Abstract shell runner - subclass for ADB or SSH."""
    def shell(self, command: str) -> str:
        raise NotImplementedError()

    def idString(self) -> str:
        raise NotImplementedError()


class AdbDevice(Device):
    """Execute commands on an Android device through ADB."""

    def __init__(self, serial: Optional[str]):
        self.serial = serial

    def adbArgs(self) -> List[str]:
        return ["adb"] + (["-s", self.serial] if self.serial else [])

    def checkConnected(self) -> None:
        code, _, _ = runLocal(self.adbArgs() + ["get-state"])
        if code != 0:
            _, devs, _ = runLocal(["adb", "devices", "-l"])
            raise RuntimeError("No ADB device detected or unauthorized. Output:\n" + devs)

    def shell(self, command: str) -> str:
        code, out, err = runLocal(self.adbArgs() + ["shell", command])
        txt = (out or "") + (("\n" + err) if err else "")
        txt = txt.replace("\r", "").strip()

        if isAdbTransportError(txt):
            runLocal(self.adbArgs() + ["reconnect"])
            time.sleep(2)
            runLocal(self.adbArgs() + ["wait-for-device"], timeout=10)
            time.sleep(1)
            code2, out2, err2 = runLocal(self.adbArgs() + ["shell", command])
            txt2 = ((out2 or "") + (("\n" + err2) if err2 else "")).replace("\r", "").strip()
            return txt2
        return txt

    def idString(self) -> str:
        return self.serial or "(unknown-serial)"


class SshDevice(Device):
    """Execute commands on a device over SSH (paramiko)."""

    def __init__(self, host: str, port: int, user: str, password: str):
        try:
            import paramiko
        except Exception:
            print("ERROR: paramiko is required for SSH mode. Install with: pip install paramiko", file=sys.stderr)
            sys.exit(1)

        self.paramiko = paramiko
        self.host = host
        self.port = port
        self.user = user
        self.password = password

        self.client = self.paramiko.SSHClient()
        self.client.load_system_host_keys()
        self.client.set_missing_host_key_policy(self.paramiko.RejectPolicy())
        try:
            self.client.connect(hostname=host, port=port, username=user,
                                password=password, look_for_keys=False,
                                allow_agent=False, timeout=20)
        except (paramiko.AuthenticationException, paramiko.SSHException, OSError) as e:
            print(f"ERROR: SSH connection failed: {e}", file=sys.stderr)
            sys.exit(1)

    def shell(self, command: str) -> str:
        try:
            # Wrap in sh -c so that pipes, redirects, &&, || all work and the
            # remote shell's PATH (including /system/bin on Android) is active.
            stdin, stdout, stderr = self.client.exec_command(
                f"sh -c {shlex.quote(command)}", timeout=30
            )
            out = stdout.read().decode("utf-8", errors="replace")
            err = stderr.read().decode("utf-8", errors="replace")
            return (out + (("\n" + err) if err else "")).strip()
        except Exception as e:
            return f"[SSH Error] {e}"

    def idString(self) -> str:
        return f"{self.user}@{self.host}:{self.port}"

    def close(self):
        try:
            self.client.close()
        except Exception:
            pass


# Common baud rates for UART auto-detection (ordered by popularity)
UART_COMMON_BAUDS = [115200, 9600, 38400, 57600, 19200, 230400, 460800, 921600, 4800, 1200]

class UartDevice(Device):
    """Execute commands on a device over UART serial console (pyserial)."""

    def __init__(self, port: str, baud: int = 0):
        try:
            import serial
        except ImportError:
            print("ERROR: pyserial is required for UART mode. Install with: pip install pyserial",
                  file=sys.stderr)
            sys.exit(1)

        self.serial_mod = serial
        self.port = port
        self.baud = baud
        self._shell_uid = None  # cached after probe

        if baud == 0:
            self.baud = self._autoBaud()

        try:
            self.conn = self.serial_mod.Serial(
                port=self.port,
                baudrate=self.baud,
                timeout=3,
                write_timeout=3,
            )
        except self.serial_mod.SerialException as e:
            print(f"ERROR: Cannot open UART port {port}: {e}", file=sys.stderr)
            sys.exit(1)

        # Flush any leftover data
        time.sleep(0.3)
        self.conn.reset_input_buffer()
        self.conn.reset_output_buffer()

    def _autoBaud(self) -> int:
        """Try common baud rates and return the first one that gives a coherent shell response."""
        print(f"{Colors.BRIGHT_CYAN}⟳ Auto-detecting baud rate on {self.port}...{Colors.RESET}")
        for rate in UART_COMMON_BAUDS:
            try:
                conn = self.serial_mod.Serial(
                    port=self.port, baudrate=rate, timeout=2, write_timeout=2
                )
                time.sleep(0.3)
                conn.reset_input_buffer()
                # Send a newline to trigger a prompt, then echo test
                conn.write(b"\n")
                time.sleep(0.3)
                conn.reset_input_buffer()
                conn.write(b"echo HARDAX_BAUD_OK\n")
                time.sleep(1)
                resp = conn.read(conn.in_waiting or 256).decode("utf-8", errors="replace")
                conn.close()
                if "HARDAX_BAUD_OK" in resp:
                    print(f"  {Colors.GREEN}✓ Detected baud rate: {rate}{Colors.RESET}")
                    return rate
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
                continue
        print(f"  {Colors.BRIGHT_RED}✗ Auto-detection failed. Defaulting to 115200.{Colors.RESET}")
        print(f"  {Colors.YELLOW}  Tip: specify --baud manually if the device uses a non-standard rate.{Colors.RESET}")
        return 115200

    _UART_MAX_BUF = 4 * 1024 * 1024  # 4 MB max buffer per command

    def _sendRecv(self, command: str, timeout: float = 10) -> str:
        """Send a command over UART and collect the output."""
        # Use a unique marker to delimit command output (hex random to avoid collisions)
        marker = f"__HARDAX_{os.urandom(8).hex()}__"
        wrapped = f"{command}; echo {marker}\n"

        self.conn.reset_input_buffer()
        self.conn.write(wrapped.encode("utf-8"))
        self.conn.flush()

        buf = b""
        marker_bytes = marker.encode("utf-8")
        deadline = time.time() + timeout
        while time.time() < deadline:
            waiting = self.conn.in_waiting
            if waiting:
                buf += self.conn.read(waiting)
                if marker_bytes in buf:
                    break
                if len(buf) > self._UART_MAX_BUF:
                    break
            else:
                time.sleep(0.1)

        text = buf.decode("utf-8", errors="replace")

        # Strip the echoed command line and the marker line.
        # Strategy: find the first line containing the marker echo command,
        # then collect everything between that line and the marker output.
        lines = text.splitlines()
        out_lines = []
        started = False
        # Build a match string from the full wrapped command for exact echo detection
        echo_sig = f"echo {marker}"
        for ln in lines:
            if not started:
                # Look for the echoed command line (contains our unique marker echo)
                if echo_sig in ln:
                    started = True
                    continue
                continue
            if marker in ln:
                break
            out_lines.append(ln)
        return "\n".join(out_lines).strip()

    def shell(self, command: str) -> str:
        try:
            return self._sendRecv(command)
        except self.serial_mod.SerialException as e:
            print(f"\n{Colors.BRIGHT_RED}✗ UART connection lost: {e}{Colors.RESET}", file=sys.stderr)
            raise RuntimeError(f"UART connection lost: {e}") from e
        except Exception as e:
            return f"[UART Error] {e}"

    def idString(self) -> str:
        return f"uart:{self.port}@{self.baud}"

    def probeShell(self) -> dict:
        """Probe the UART shell environment and return info dict."""
        info = {}
        info["uid"] = self._sendRecv("id 2>/dev/null").strip()
        info["shell"] = self._sendRecv("which sh 2>/dev/null || command -v sh 2>/dev/null").strip()
        info["bash"] = self._sendRecv("which bash 2>/dev/null || command -v bash 2>/dev/null").strip()
        info["uname"] = self._sendRecv("uname -a 2>/dev/null").strip()
        info["is_root"] = "uid=0(" in info.get("uid", "")
        info["is_android"] = self._sendRecv(
            "test -f /system/build.prop && echo YES 2>/dev/null"
        ).strip() == "YES"
        info["has_getprop"] = self._sendRecv(
            "command -v getprop >/dev/null 2>&1 && echo YES"
        ).strip() == "YES"
        info["has_busybox"] = self._sendRecv(
            "command -v busybox >/dev/null 2>&1 && echo YES"
        ).strip() == "YES"
        info["has_toybox"] = self._sendRecv(
            "command -v toybox >/dev/null 2>&1 && echo YES"
        ).strip() == "YES"
        info["path"] = self._sendRecv("echo $PATH").strip()
        self._shell_uid = info["uid"]
        return info

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  COMMAND EXECUTION ENGINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def applyFilters(output: str, original: str) -> str:
    """
    Emulate a shell pipeline (grep, head, tail) in Python so we can
    re-apply filters on locally captured command output.
    """
    if not output:
        return output

    lines = output.splitlines()

    pipe = ""
    if "|" in original:
        pipe = original.split("|", 1)[1]
    if not pipe:
        return "\n".join(lines)

    stages = [s.strip() for s in pipe.split("|") if s.strip()]

    headN = None
    tailN = None
    greps = []

    for st in stages:
        if st.startswith("grep"):
            mflags = re.search(r"(^|\s)-([iEvF]+)", st)
            flags = set(mflags.group(2)) if mflags else set()
            pm = re.search(r"""'(.*?)'|"(.*?)"|(\S+)$""", st)
            if not pm:
                continue
            pattern = pm.group(1) or pm.group(2) or pm.group(3)
            greps.append((flags, pattern))
        elif st.startswith("head"):
            m = re.search(r"head\s+-?(\d+)", st)
            if m:
                headN = int(m.group(1))
        elif st.startswith("tail"):
            m = re.search(r"tail\s+-?(\d+)", st)
            if m:
                tailN = int(m.group(1))

    filtered = lines
    for flags, pattern in greps:
        ignoreCase = "i" in flags
        invert = "v" in flags
        fixed = "F" in flags

        if fixed:
            needle = pattern if not ignoreCase else pattern.lower()
            def matchFn(s, _n=needle, _ic=ignoreCase):
                h = s if not _ic else s.lower()
                return _n in h
        else:
            try:
                rx = re.compile(pattern, re.IGNORECASE if ignoreCase else 0)
                def matchFn(s, _rx=rx):
                    return bool(_rx.search(s))
            except re.error:
                needle = pattern if not ignoreCase else pattern.lower()
                def matchFn(s, _n=needle, _ic=ignoreCase):
                    h = s if not _ic else s.lower()
                    return _n in h

        if invert:
            filtered = [ln for ln in filtered if not matchFn(ln)]
        else:
            filtered = [ln for ln in filtered if matchFn(ln)]

    if tailN is not None and tailN > 0:
        filtered = filtered[-tailN:]
    elif tailN == 0:
        filtered = []
    if headN is not None and headN >= 0:
        filtered = filtered[:headN]

    return "\n".join(filtered)


def executeWithFallback(device: Device, command: str,
                        showCommands: bool = False,
                        isRooted: Optional[bool] = None,
                        rootMethod: str = "none") -> str:
    """
    Smart execution for netstat/ss network commands.
    Tries multiple strategies: root → non-root → drop -p → swap tool.
    Non-network commands pass straight through.
    """

    def isNetOrSs(cmd: str) -> bool:
        cl = cmd.lower()
        return ("netstat" in cl) or bool(re.search(r"\bss\b", cl))

    def splitAlternatives(src: str) -> list:
        s = re.sub(
            r"^\s*(?:/system/bin/)?sh\s+-[a-z]*c\s+(['\"])(.*?)\1\s*$",
            r"\2", src.strip(), flags=re.IGNORECASE,
        )
        s = s.replace("\r\n", "\n").replace("\r", "\n")
        blocks = re.split(r"\n\s*\n+", s.strip())
        return [b for b in blocks if isNetOrSs(b)]

    def splitPipeline(block: str):
        if "|" not in block:
            return block.strip(), ""
        base, rest = block.split("|", 1)
        return base.strip(), ("|" + rest.strip())

    def dropPidFlag(cmd: str) -> str:
        def _rmP(m):
            f = m.group(1)
            f2 = f.replace("p", "")
            return "-" + f2 if f2 else ""
        return re.sub(r"\s-(\w+)", _rmP, cmd)

    def swapTool(cmd: str):
        if re.match(r"(?i)^\s*netstat\b", cmd):
            return re.sub(r"(?i)^\s*netstat\b", "ss", cmd, count=1)
        if re.match(r"(?i)^\s*ss\b", cmd):
            return re.sub(r"(?i)^\s*ss\b", "netstat", cmd, count=1)
        return None

    def outputReason(txt: str):
        if not txt or not txt.strip():
            return False, "empty output"
        lower = txt.lower()
        for bad in ["not found", "invalid", "permission denied", "cannot open", "no such"]:
            if bad in lower:
                return False, bad
        lines = [l for l in txt.strip().split("\n") if l.strip()]
        if len(lines) <= 1 and lines and ("proto" in lines[0].lower() or "state" in lines[0].lower()):
            return False, "header-only"
        return True, "ok"

    # Non-network commands go straight through
    if not isNetOrSs(command):
        if NET_DEBUG:
            print("[net-debug] non-network command -> bypass executor")
        return device.shell(command)

    blocks = splitAlternatives(command)
    if NET_DEBUG:
        print("[net-debug] alternatives: %d block(s)" % len(blocks))
    if not blocks:
        return device.shell(command)

    _nativeSu = rootMethod not in ("uart-root", "ssh-root", "adbd-root")

    def _suWrap(cmd: str) -> str:
        return "su -c %s" % shlex.quote(cmd)

    for block in blocks:
        baseCmd, pipeline = splitPipeline(block)

        candidates = []
        if _nativeSu and (isRooted or isRooted is None):
            candidates.append(_suWrap(baseCmd))
        candidates.append(baseCmd)

        noP = dropPidFlag(baseCmd)
        if noP != baseCmd:
            if _nativeSu and (isRooted or isRooted is None):
                candidates.append(_suWrap(noP))
            candidates.append(noP)

        swapped = swapTool(baseCmd)
        if swapped:
            if _nativeSu and (isRooted or isRooted is None):
                candidates.append(_suWrap(swapped))
            candidates.append(swapped)
            swappedNoP = dropPidFlag(swapped)
            if swappedNoP != swapped:
                if _nativeSu and (isRooted or isRooted is None):
                    candidates.append(_suWrap(swappedNoP))
                candidates.append(swappedNoP)

        if NET_DEBUG:
            print("[net-debug] candidates (%d):" % len(candidates))
            for c in candidates:
                print("  - %s" % c)

        for cand in candidates:
            if showCommands:
                print("  -> Trying: %s" % cand)
            raw = device.shell(cand)
            ok, why = outputReason(raw)
            if not ok:
                if NET_DEBUG:
                    print("[net-debug] reject: %s" % why)
                continue
            if NET_DEBUG:
                print("[net-debug] winner: %s" % cand)
            pipelineSrc = baseCmd + (" " + pipeline if pipeline else "")
            return applyFilters(raw, pipelineSrc)

    return ""


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  ROOT DETECTION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def detectRootStatus(device: Device) -> Tuple[bool, str]:
    """
    Probe the device for root access.
    Returns (isRooted, method) where method is one of:
        uart-root | ssh-root | adbd-root | magisk | su | su-present-not-working | none
    """

    # 0a. UART sessions already running as root - no su needed
    if isinstance(device, UartDevice):
        out = device.shell("id 2>/dev/null").strip()
        if out and ("uid=0(" in out or out.split()[0:1] == ["uid=0"]):
            return True, "uart-root"
        # Not root over UART - fall through to su probing below

    # 0b. SSH sessions already running as root - no su needed
    if isinstance(device, SshDevice):
        out = device.shell("id 2>/dev/null").strip()
        if out and ("uid=0(" in out or out.split()[0:1] == ["uid=0"]):
            return True, "ssh-root"
        # Not root over SSH - fall through to su probing below

    # 1. Try ADBD root (eng / userdebug builds)
    try:
        if isinstance(device, AdbDevice):
            runLocal(["adb", "start-server"])
            runLocal(device.adbArgs() + ["root"])
            out = device.shell("id 2>/dev/null")
            if out and ("uid=0(" in out or out.strip() == "0"):
                return True, "adbd-root"
    except Exception:
        pass

    # 2. Check for su binary existence
    suPath = device.shell("command -v su 2>/dev/null || which su 2>/dev/null").strip()
    hasSu = bool(suPath and "not found" not in suPath.lower())

    # Feature-detect timeout and cut
    try:
        hasTimeout = "yes" in device.shell(
            "command -v timeout >/dev/null 2>&1 && echo yes || echo no"
        ).strip().lower()
    except Exception:
        hasTimeout = False
    try:
        hasCut = "yes" in device.shell(
            "command -v cut >/dev/null 2>&1 && echo yes || echo no"
        ).strip().lower()
    except Exception:
        hasCut = False

    def suCmd(cmd: str, seconds: int = 2) -> str:
        q = shlex.quote(cmd)
        if hasTimeout:
            return device.shell(f"timeout {seconds} su -c {q} 2>/dev/null")
        return device.shell(f"su -c {q} 2>/dev/null")

    if hasSu:
        # 3a. Proof by UID
        out = suCmd("id -u", 2).strip()
        if out == "0":
            ver = suCmd("magisk --version", 2).strip() or suCmd("magisk -v", 2).strip()
            return (True, "magisk") if ver else (True, "su")

        # 3b. Proof by canonical id string
        idOut = suCmd("id", 2)
        if idOut and ("uid=0(" in idOut or "uid=0" in idOut):
            if "context=u:r:magisk:s0" in idOut:
                return True, "magisk"
            ver = suCmd("magisk --version", 2).strip() or suCmd("magisk -v", 2).strip()
            return (True, "magisk") if ver else (True, "su")

        # 3c. Proof by cut-parsed username
        if hasCut:
            who = suCmd("id | cut -d'(' -f2 | cut -d')' -f1", 2).strip()
            if who.lower() == "root":
                if not idOut:
                    idOut = suCmd("id", 2)
                if idOut and "context=u:r:magisk:s0" in idOut:
                    return True, "magisk"
                ver = suCmd("magisk --version", 2).strip() or suCmd("magisk -v", 2).strip()
                return (True, "magisk") if ver else (True, "su")

        return False, "su-present-not-working"

    return False, "none"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  DEVICE INFORMATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _getPropFallback(device: Device, props: List[str]) -> str:
    for p in props:
        v = device.shell(f"getprop {p}").strip()
        if v:
            return v
    return "(unknown)"


def _getPropWithCpuinfo(device: Device, props: List[str]) -> str:
    for p in props:
        v = device.shell(f"getprop {p}").strip()
        if v:
            return v
    cpuinfo = device.shell("cat /proc/cpuinfo")
    m = re.search(r"(?i)hardware\s*:\s*(.+)", cpuinfo)
    if m:
        return m.group(1).strip()
    return "(unknown)"


def collectDeviceInfo(device: Device) -> Dict[str, str]:
    """Pull essential device metadata for the report header."""
    model = _getPropFallback(device, ["ro.product.model", "ro.product.device", "ro.product.name"])
    brand = _getPropFallback(device, ["ro.product.brand", "ro.product.manufacturer"])
    manufacturer = _getPropFallback(device, ["ro.product.manufacturer", "ro.product.brand"])
    name = _getPropFallback(device, ["ro.product.name", "ro.product.model"])
    socManufacturer = _getPropFallback(device, ["ro.soc.manufacturer", "ro.board.platform", "ro.hardware"])
    socModel = _getPropWithCpuinfo(device, ["ro.soc.model", "ro.hardware", "ro.board.platform"])
    androidVersion = device.shell("getprop ro.build.version.release").strip()
    sdkLevel = device.shell("getprop ro.build.version.sdk").strip()
    buildId = device.shell("getprop ro.build.display.id").strip()
    fingerprint = device.shell("getprop ro.build.fingerprint").strip()
    serialno = device.shell("getprop ro.serialno").strip() or device.shell("getprop ro.boot.serialno").strip()
    timezone = device.shell("getprop persist.sys.timezone").strip()

    return {
        "model": model,
        "brand": brand,
        "manufacturer": manufacturer,
        "name": name,
        "soc_manufacturer": socManufacturer,
        "soc_model": socModel,
        "android_version": androidVersion,
        "sdk_level": sdkLevel,
        "build_id": buildId,
        "fingerprint": fingerprint,
        "serialno": serialno,
        "timezone": timezone,
    }


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  JSON CHECK LOADING & VALIDATION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _loadChecksFromFile(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        checks = data
    elif isinstance(data, dict) and isinstance(data.get("checks"), list):
        checks = data["checks"]
    else:
        raise ValueError(f"{os.path.basename(path)} must be a list or an object with 'checks' array")

    valid = []
    for i, c in enumerate(checks, start=1):
        if not isinstance(c, dict):
            continue
        if not REQUIRED_CHECK_KEYS.issubset(c.keys()):
            missing = REQUIRED_CHECK_KEYS - set(c.keys())
            raise ValueError(f"{os.path.basename(path)}: check #{i} missing keys: {', '.join(sorted(missing))}")
        valid.append(c)
    return valid


def loadChecks(jsonPath: Optional[str], jsonDir: Optional[str]) -> List[Dict[str, Any]]:
    """Load and merge security checks from JSON file(s)."""
    merged: List[Dict[str, Any]] = []

    if jsonPath:
        if not os.path.isfile(jsonPath):
            print(f"ERROR: JSON file not found: {jsonPath}", file=sys.stderr)
            sys.exit(1)
        try:
            merged.extend(_loadChecksFromFile(jsonPath))
        except Exception as e:
            print(f"ERROR parsing {jsonPath}: {e}", file=sys.stderr)
            sys.exit(1)

    if jsonDir:
        if not os.path.isdir(jsonDir):
            print(f"ERROR: JSON directory not found: {jsonDir}", file=sys.stderr)
            sys.exit(1)
        for fname in sorted(os.listdir(jsonDir)):
            if not fname.lower().endswith(".json"):
                continue
            fpath = os.path.join(jsonDir, fname)
            try:
                merged.extend(_loadChecksFromFile(fpath))
            except Exception as e:
                print(f"ERROR parsing {fpath}: {e}", file=sys.stderr)
                sys.exit(1)

    if not merged:
        print("ERROR: No checks loaded. Provide --json or --json-dir.", file=sys.stderr)
        sys.exit(1)

    # Surface checks whose safe_pattern is not a valid regex. Such checks
    # silently degrade to substring matching at run time, which can flip
    # SAFE/CRITICAL results — warn so authors can fix them.
    patternIssues: List[str] = []
    for chk in merged:
        patternIssues.extend(validateCheckPattern(chk))
    if patternIssues:
        print(f"{Colors.YELLOW}⚠ {len(patternIssues)} check(s) have invalid safe_pattern "
              f"regex (will fall back to substring match):{Colors.RESET}", file=sys.stderr)
        for msg in patternIssues[:10]:
            print(f"  {msg}", file=sys.stderr)
        if len(patternIssues) > 10:
            print(f"  ... and {len(patternIssues) - 10} more", file=sys.stderr)

    return merged


def validateCheckPattern(check: Dict[str, Any]) -> List[str]:
    """Validate safe_pattern regex for a single check definition."""
    issues = []
    pattern = check.get("safe_pattern", "")
    label = check.get("label", "unknown")
    if not pattern:
        return issues
    try:
        re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)
    except re.error as e:
        issues.append(f"[{label}] Invalid regex: {e}")
    return issues


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CHECK EVALUATION ENGINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def isNullResponse(output: str) -> bool:
    """Detect settings/getprop returning literal 'null'."""
    if not output:
        return False
    return output.lower().strip() in ["null", "none", "(null)", "(none)"]


def isEmptyOrError(output: str) -> bool:
    """Detect empty output or common error strings from the device."""
    if not output:
        return True
    if isAdbTransportError(output):
        return True
    lower = output.lower().strip()
    errorIndicators = [
        "not found", "no such", "error", "exception",
        "permission denied", "invalid", "failed",
        "inaccessible", "cmd: can't find", "can't find service",
        "not supported", "service not found", "does not exist", "no output",
    ]
    if lower in ["", "(empty)", "unknown"]:
        return True
    for indicator in errorIndicators:
        if indicator in lower and len(lower) < 100:
            return True
    return False


def runChecks(device: Device, checks: List[Dict[str, Any]],
              onProgress=None, showCommands: bool = False,
              isRooted: bool = False,
              rootMethod: str = "none",
              dashboard: Optional['HUDDashboard'] = None) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """
    Execute every check against the device and classify the result.
    Returns (rows, counts) where rows is the full audit data.
    """
    rows: List[Dict[str, Any]] = []
    counts = {"safe": 0, "warning": 0, "critical": 0, "info": 0, "verify": 0, "skipped": 0}
    total = len(checks)
    startTime = time.time()
    consecutiveAdbErrors = 0
    _lastCategory = None   # tracks category for section headers

    for idx, chk in enumerate(checks, start=1):
        category = chk.get("category", "General")
        label = chk.get("label", "Unnamed")
        command = chk.get("command", "")
        safePattern = chk.get("safe_pattern", "")
        level = chk.get("level", "info")
        desc = chk.get("description", "")
        emptyIsSafe = chk.get("empty_is_safe", False)
        requiresOutput = chk.get("requires_output", True)
        nullIsSafe = chk.get("null_is_safe", False)

        raw = executeWithFallback(device, command, showCommands, isRooted=isRooted, rootMethod=rootMethod) if command else ""

        # ADB transport error - SKIPPED
        if raw and isAdbTransportError(raw):
            consecutiveAdbErrors += 1
            status = "SKIPPED"
            counts["skipped"] += 1
            raw = f"[ADB ERROR] {raw.strip()}"
            matched = False
            needsVerification = False
            bucket = bucketFromLevel(level)
            outputIsNull = False

            if consecutiveAdbErrors >= 5:

                print(f"\n  {Colors.BRIGHT_RED}✗ Device unresponsive after {consecutiveAdbErrors} consecutive ADB errors.{Colors.RESET}")
                print(f"  {Colors.YELLOW}  Attempting reconnect...{Colors.RESET}")
                if isinstance(device, AdbDevice):
                    runLocal(device.adbArgs() + ["reconnect"])
                    time.sleep(3)
                    runLocal(device.adbArgs() + ["wait-for-device"], timeout=15)
                    time.sleep(2)
                    testCode, testOut, _ = runLocal(device.adbArgs() + ["shell", "echo HARDAX_ALIVE"], timeout=5)
                    if "HARDAX_ALIVE" in (testOut or ""):
                        print(f"  {Colors.GREEN}  ✓ Device reconnected! Resuming...{Colors.RESET}")
                        consecutiveAdbErrors = 0
                    else:
                        print(f"  {Colors.BRIGHT_RED}  ✗ Device still offline. Skipping remaining checks.{Colors.RESET}")
                        rows.append({
                            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                            "category": category, "label": label, "level": level,
                            "bucket": bucket, "status": "SKIPPED", "matched": "False",
                            "command": command, "result": raw,
                            "description": desc + " [⊘ Skipped - ADB connection lost]",
                            "needs_verification": False,
                        })
                        for remainingChk in checks[idx:]:
                            rows.append({
                                "category": remainingChk.get("category", "General"),
                                "label": remainingChk.get("label", "Unnamed"),
                                "command": remainingChk.get("command", ""),
                                "result": "[SKIPPED] Device offline - ADB connection lost",
                                "status": "SKIPPED",
                                "description": remainingChk.get("description", ""),
                            })
                            counts["skipped"] += 1
                        break
        # Service not found error (e.g. "Can't find service: bluetooth_manager") - SKIPPED
        elif raw and isServiceError(raw):
            status = "SKIPPED"
            counts["skipped"] += 1
            raw = f"[SERVICE N/A] {raw.strip()}"
            matched = False
            needsVerification = False
            bucket = bucketFromLevel(level)
            outputIsNull = False
        else:
            consecutiveAdbErrors = 0
            normalized = normalizeForMatch(raw).strip()
            bucket = bucketFromLevel(level)
            matched = False
            needsVerification = False

            outputEmpty = isEmptyOrError(raw)
            outputIsNull = isNullResponse(raw)

            if safePattern:
                try:
                    matched = bool(re.search(safePattern, normalized,
                                             re.IGNORECASE | re.MULTILINE | re.DOTALL))
                except re.error:
                    matched = safePattern.lower() in normalized.lower()

            # Determine status
            if outputIsNull:
                nullInPattern = safePattern and "null" in safePattern.lower()
                if nullIsSafe or nullInPattern:
                    status = "SAFE"
                    counts["safe"] += 1
                else:
                    status = "VERIFY"
                    counts["verify"] += 1
                    needsVerification = True
            elif matched:
                status = "SAFE"
                counts["safe"] += 1
            elif outputEmpty:
                if emptyIsSafe:
                    status = "SAFE"
                    counts["safe"] += 1
                elif requiresOutput and bucket in ("critical", "warning"):
                    status = "VERIFY"
                    counts["verify"] += 1
                    needsVerification = True
                else:
                    status = "INFO"
                    counts["info"] += 1
            else:
                if bucket == "critical":
                    status = "CRITICAL"
                    counts["critical"] += 1
                elif bucket == "warning":
                    status = "WARNING"
                    counts["warning"] += 1
                else:
                    status = "INFO"
                    counts["info"] += 1

        # Live output
        try:
            elapsed = time.time() - startTime
            avgTime  = elapsed / idx if idx > 0 else 0
            remaining = int(avgTime * (total - idx))
            etaStr   = f"{remaining // 60}m{remaining % 60:02d}s" if remaining >= 60 else f"{remaining}s"
            percentage = (idx / total) * 100

            sc, sym = HUDDashboard._STATUS_FMT.get(status, (Colors.CYAN, "ℹ"))

            if showCommands:
                # Category header when section changes
                if category != _lastCategory:
                    if _lastCategory is not None:
                        print()
                    catLabel = category.upper()
                    # Count checks in this category
                    catTotal = sum(1 for c in checks if c.get("category", "General") == category)
                    print(f"  {Colors.BRIGHT_CYAN}┌{'─' * 68}┐{Colors.RESET}")
                    print(f"  {Colors.BRIGHT_CYAN}│{Colors.RESET} {Colors.BOLD}{Colors.BRIGHT_WHITE}{catLabel}{Colors.RESET}"
                          f"{Colors.DIM} ({catTotal} checks){Colors.RESET}"
                          f"{'':>{max(1, 60 - len(catLabel) - len(str(catTotal)))}}"
                          f"{Colors.BRIGHT_CYAN}│{Colors.RESET}")
                    print(f"  {Colors.BRIGHT_CYAN}└{'─' * 68}┘{Colors.RESET}")
                    _lastCategory = category

                # Per-check line with counter
                rPreview = (raw or "").strip().split("\n")[0].replace("\r", "")
                if len(rPreview) > 30:
                    rPreview = rPreview[:29] + "…"

                lbl = label[:40] + "…" if len(label) > 40 else label
                counter = f"[{idx:03d}/{total}]"
                print(
                    f"  {Colors.DIM}{counter}{Colors.RESET} "
                    f"{sc}{sym}{Colors.RESET} "
                    f"{Colors.BRIGHT_WHITE}{lbl:<41}{Colors.RESET} "
                    f"{Colors.DIM}→ {Colors.RESET}{sc}{rPreview or '(empty)'}{Colors.RESET}"
                )

                # For critical/warning show the command and remediation
                if status in ("CRITICAL", "WARNING") and command:
                    cmdShort = command[:60] + "…" if len(command) > 60 else command
                    print(f"  {Colors.DIM}{'':>10} └─ $ {cmdShort}{Colors.RESET}")
                    remText = chk.get("remediation", "")
                    if remText:
                        remShort = remText[:70] + "…" if len(remText) > 70 else remText
                        print(f"  {Colors.CYAN}{'':>10} └─ Fix: {remShort}{Colors.RESET}")

            elif dashboard:
                # HUD Tactical Dashboard mode
                dashboard.onCheckComplete(category, label, status)

            else:
                # Compact progress bar fallback (no dashboard, no --show-commands)
                barWidth = 24
                filled = int((idx / total) * barWidth)
                bar = "█" * filled + "░" * (barWidth - filled)
                sys.stdout.write(
                    f"\r  {Colors.BRIGHT_BLUE}[{bar}]{Colors.RESET} "
                    f"{Colors.BRIGHT_WHITE}{idx:3d}/{total}{Colors.RESET} "
                    f"{Colors.DIM}({percentage:4.1f}%){Colors.RESET}  "
                    f"{Colors.GREEN}✓{counts['safe']:<4}{Colors.RESET}"
                    f"{Colors.BRIGHT_RED}✗{counts['critical']:<3}{Colors.RESET}"
                    f"{Colors.YELLOW}⚠{counts['warning']:<3}{Colors.RESET}"
                    f"{Colors.BRIGHT_MAGENTA}?{counts['verify']:<3}{Colors.RESET}"
                    f"  {Colors.DIM}ETA {etaStr}{Colors.RESET}  "
                )
                sys.stdout.flush()

            if onProgress:
                onProgress(idx, total)
        except Exception:
            pass

        # Build row
        displayDesc = desc
        displayResult = raw
        if needsVerification:
            if outputIsNull:
                displayDesc = desc + " [⚠ Manual verification required - value is NULL]"
                displayResult = "null (Setting may not exist or is not configured)"
            else:
                displayDesc = desc + " [⚠ Manual verification required - empty/unsupported output]"
                if not raw.strip():
                    displayResult = "(No output - command may not be supported on this device)"

        rows.append({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "category": category,
            "label": label,
            "level": level,
            "bucket": bucket,
            "status": status,
            "matched": str(matched),
            "command": command,
            "result": displayResult,
            "description": displayDesc,
            "needs_verification": needsVerification,
            "remediation": chk.get("remediation", ""),
        })

    print()
    return rows, counts


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  Trusted Certificate Policy Audit (No limit version, same style)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _findCertFiles(device: Device) -> List[str]:
    """Search standard Android CA directories for certificate files (deduped)."""
    candidates = [
        "/system/etc/security/cacerts",
        "/system/etc/security/cacerts_google",
        "/apex/com.android.conscrypt/cacerts",
        "/apex/com.android.conscrypt/etc/security/cacerts",
        "/vendor/etc/security/cacerts",        # seen on some builds
        "/product/etc/security/cacerts",       # seen on some builds

        # User-installed CA stores
        "/data/misc/user/0/cacerts-added",

        # Legacy stores
        "/data/misc/keychain/cacerts-added",
        "/data/misc/keychain",

        # Keystore directories
        "/data/misc/keystore/user_0",
    ]

    files = []
    seen = set()
    for base in candidates:
        listing = device.shell(f"ls -1 {base} 2>/dev/null")
        names = [n.strip() for n in (listing.splitlines() if listing else []) if n.strip()]
        matched = []
        for n in names:
            if n.endswith(".0") or re.fullmatch(r"[0-9a-fA-F]{1,8}", n):
                full = f"{base}/{n}"
                if full not in seen:
                    seen.add(full)
                    matched.append(full)
        files.extend(matched)
        if CERT_DEBUG:
            print(f"[cert-debug] {base}: {len(matched)} files matched")

    if CERT_DEBUG:
        print(f"[cert-debug] total unique cert files discovered: {len(files)}")

    return files


def _readCertBytes(device: Device, path: str):
    """Read certificate bytes from device, trying PEM first then DER via base64."""
    # Try PEM first
    txt = device.shell(f"cat {path} 2>/dev/null")
    if txt and "-----BEGIN CERTIFICATE-----" in txt:
        return txt.encode("utf-8"), "PEM"

    # Try DER by base64 from device (several common variants)
    candidates = [
        f"base64 {path} 2>/dev/null",
        f"toybox base64 {path} 2>/dev/null",
        f"busybox base64 {path} 2>/dev/null",
        f"dd if='{path}' bs=4096 2>/dev/null | base64 2>/dev/null",
        f"dd if='{path}' bs=4096 2>/dev/null | toybox base64 2>/dev/null",
        f"dd if='{path}' bs=4096 2>/dev/null | busybox base64 2>/dev/null",
    ]
    for cmd in candidates:
        b64 = device.shell(cmd)
        if b64 and "not found" not in b64.lower() and b64.strip():
            try:
                cleaned = "".join(b64.strip().split())
                if cleaned:
                    return base64.b64decode(cleaned, validate=False), "DER"
            except Exception:
                # try next variant
                pass

    # Final lightweight hex fallback (if present on device)
    for cmd in [
        f"xxd -p {path} 2>/dev/null",
        f"hexdump -v -e '1/1 \"%02x\"' {path} 2>/dev/null",
        f"od -An -tx1 -v {path} 2>/dev/null | tr -d ' \\n' 2>/dev/null",
    ]:
        hx = device.shell(cmd)
        if hx and re.fullmatch(r"[0-9a-fA-F]+", hx.strip()):
            try:
                return bytes.fromhex(hx.strip()), "DER"
            except Exception:
                pass

    return None, None


def auditCertificates(device: Device) -> List[Dict[str, Any]]:
    """Pull and analyze system + user certificates from the device (no artificial limit)."""
    certs: List[Dict[str, Any]] = []
    import warnings
    from cryptography.utils import CryptographyDeprecationWarning
    warnings.filterwarnings('ignore', category=CryptographyDeprecationWarning)
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except Exception:
        if CERT_DEBUG:
            print("[cert-debug] cryptography not available; skipping cert parse")
        return []

    certFiles = _findCertFiles(device)
    if CERT_DEBUG:
        print(f"[cert-debug] discovered total: {len(certFiles)}")
    today = datetime.now()

    # IMPORTANT: No limit - process every discovered cert file
    for certPath in certFiles:
        try:
            rawBytes, kind = _readCertBytes(device, certPath)
            if not rawBytes:
                continue

            cert = None
            if kind == "PEM":
                try:
                    cert = x509.load_pem_x509_certificate(rawBytes, default_backend())
                except Exception:
                    cert = None
            if cert is None:
                try:
                    cert = x509.load_der_x509_certificate(rawBytes, default_backend())
                except Exception:
                    cert = None
            if cert is None:
                continue

            subject = getattr(cert, "subject", None)
            issuer = getattr(cert, "issuer", None)
            try:
                notBefore = getattr(cert, 'not_valid_before_utc')
                notAfter  = getattr(cert, 'not_valid_after_utc')
            except Exception:
                notBefore = getattr(cert, 'not_valid_before', None)
                notAfter  = getattr(cert, 'not_valid_after', None)
            if notBefore is None or notAfter is None:
                continue

            # Normalize tz-awareness to naive
            nb = notBefore.replace(tzinfo=None)
            na = notAfter.replace(tzinfo=None)

            try:
                subjectStr = subject.rfc4514_string() if subject else "Unknown"
                issuerStr  = issuer.rfc4514_string()  if issuer  else "Unknown"
            except Exception:
                subjectStr = "Unknown"
                issuerStr  = "Unknown"

            daysOld = (today - nb).days
            daysUntilExpiry = (na - today).days

            if daysUntilExpiry < 0:
                status, risk = "EXPIRED", "critical"
            elif daysUntilExpiry < 30:
                status, risk = "EXPIRING_SOON", "warning"
            elif daysUntilExpiry < 90:
                status, risk = "CHECK", "warning"
            else:
                status, risk = "VALID", "safe"

            cn = "Unknown"
            for part in subjectStr.split(","):
                p = part.strip()
                if p.startswith("CN="):
                    cn = p[3:]
                    break

            certs.append({
                "filename": certPath.split("/")[-1],
                "cn": cn[:50] + "..." if len(cn) > 50 else cn,
                "issuer": issuerStr[:50] + "..." if len(issuerStr) > 50 else issuerStr,
                "not_before": nb.strftime("%Y-%m-%d"),
                "not_after": na.strftime("%Y-%m-%d"),
                "days_old": daysOld,
                "days_until_expiry": daysUntilExpiry,
                "status": status,
                "risk": risk,
            })
        except Exception:
            # keep going on any single-file error
            continue

    # User-installed certs across all profiles (filenames only; requires root to list others)
    try:
        userRoots = device.shell("ls -d /data/misc/user/*/cacerts-added 2>/dev/null")
        userDirs = [d.strip() for d in (userRoots.split("\n") if userRoots else []) if d.strip()]
        if not userDirs:
            userDirs = ["/data/misc/user/0/cacerts-added"]
        for d in userDirs:
            ulist = device.shell(f"ls -1 {d} 2>/dev/null")
            if ulist and ulist.strip():
                for cf in [x.strip() for x in ulist.split("\n") if x.strip()]:
                    certs.append({
                        "filename": cf,
                        "cn": "USER INSTALLED CERT",
                        "issuer": "Unknown - User Added",
                        "not_before": "-",
                        "not_after": "-",
                        "days_old": 0,
                        "days_until_expiry": 0,
                        "status": "USER_CERT",
                        "risk": "critical",
                    })
    except Exception:
        pass

    # Sort: critical first, then warning, then by days until expiry
    return sorted(certs, key=lambda x: (x["risk"] != "critical", x["risk"] != "warning", x["days_until_expiry"]))

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  REPORT GENERATION - TXT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def writeTxtReport(path: str, deviceInfo: Dict[str, str],
                   rows: List[Dict[str, Any]], counts: Dict[str, int],
                   certs: List[Dict[str, Any]], deviceIdStr: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"HARDAX - Hardening Audit eXaminer Report\nGenerated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("Device Information\n" + "=" * 40 + "\n")
        for k in ["model", "brand", "manufacturer", "name", "soc_manufacturer", "soc_model",
                   "android_version", "sdk_level", "build_id", "fingerprint", "serialno", "timezone"]:
            f.write(f"{k.replace('_', ' ').title()}: {deviceInfo.get(k, '')}\n")

        if certs:
            f.write("\n" + "=" * 40 + "\nTrusted Certificate Policy Audit\n" + "=" * 40 + "\n")
            f.write(f"{'CN':<40} {'Valid From':<12} {'Valid Until':<12} {'Days Old':>10} {'Expiry':>10} {'Status':<15}\n")
            f.write("-" * 100 + "\n")
            for c in certs:
                daysOld = str(c["days_old"]) if isinstance(c["days_old"], int) else "-"
                daysExp = str(c["days_until_expiry"]) if isinstance(c["days_until_expiry"], int) else "-"
                f.write(f"{c['cn']:<40} {c['not_before']:<12} {c['not_after']:<12} {daysOld:>10} {daysExp:>10} {c['status']:<15}\n")

        f.write("\n" + "=" * 40 + "\nFindings\n" + "=" * 40 + "\n")
        for r in rows:
            f.write(f"\n[{r['category']}] {r['label']}\n")
            f.write(f"Command: {r['command']}\n")
            f.write(f"Description: {r['description']}\n")
            f.write(f"Result: {r['result'][:500]}{'...' if len(r['result']) > 500 else ''}\n")
            f.write(f"Status: {r['status']}\n")
            if r.get("remediation") and r["status"] not in ("SAFE", "INFO"):
                f.write(f"Remediation: {r['remediation']}\n")
            f.write("-" * 40 + "\n")

        f.write("\n" + "=" * 40 + "\n")
        f.write("AUDIT SUMMARY\n")
        f.write(f"Target: {deviceIdStr}\n")
        f.write(f"Safe: {counts['safe']} | Warnings: {counts['warning']} | Critical: {counts['critical']} | Info: {counts['info']} | Skipped: {counts.get('skipped', 0)}\n")
        if certs:
            expired = sum(1 for c in certs if c["status"] == "EXPIRED")
            userCerts = sum(1 for c in certs if c["status"] == "USER_CERT")
            f.write(f"Certificates: {len(certs)} total | {expired} expired | {userCerts} user-installed\n")
        f.write("=" * 40 + "\n")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  REPORT GENERATION - CSV
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def writeCsvReport(path: str, rows: List[Dict[str, Any]]) -> None:
    fieldnames = ["timestamp", "category", "label", "level", "bucket", "status",
                  "matched", "command", "result", "description", "remediation"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})


def writeJsonReport(path: str, deviceInfo: Dict[str, str],
                    rows: List[Dict[str, Any]], counts: Dict[str, int],
                    certs: Optional[List[Dict[str, Any]]],
                    target: str) -> None:
    """Write a machine-readable JSON report for CI / tooling consumption."""
    payload = {
        "version": __version__,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": target,
        "device": deviceInfo or {},
        "counts": counts,
        "checks": rows,
        "certificates": certs or [],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  REPORT GENERATION - HTML (Hacker Aesthetic)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def writeHtmlReport(htmlPath: str, deviceInfo: Dict[str, str],
                    rows: List[Dict[str, Any]], counts: Dict[str, int],
                    certs: Optional[List[Dict[str, Any]]] = None) -> None:
    """Generate an interactive HTML report with hacker aesthetic and severity toggles."""

    # Certificate section
    certRowsHtml = ""
    expiredCount = expiringCount = userCount = validCount = 0

    if certs:
        certParts = []
        for c in certs:
            riskClass = c["risk"]
            statusEmoji = {"EXPIRED": "🔴", "EXPIRING_SOON": "🟡", "CHECK": "🟡",
                           "USER_CERT": "⚠️", "VALID": "🟢"}.get(c["status"], "⚪")
            daysInfo = f"{c['days_old']:,}" if isinstance(c["days_old"], int) else "-"
            expiryInfo = f"{c['days_until_expiry']:,}" if isinstance(c["days_until_expiry"], int) else "-"
            certParts.append(
                f'<tr class="cert-row {riskClass}" data-status="{riskClass.upper()}" data-search="{htmlEscape(c["cn"].lower())} {htmlEscape(c["issuer"].lower())}">'
                f'<td>{htmlEscape(c["cn"])}</td>'
                f'<td>{htmlEscape(c["not_before"])}</td>'
                f'<td>{htmlEscape(c["not_after"])}</td>'
                f'<td class="mono-right">{daysInfo}</td>'
                f'<td class="mono-right">{expiryInfo}</td>'
                f'<td><span class="cert-status {riskClass}">{statusEmoji} {c["status"]}</span></td>'
                f"</tr>"
            )
        certRowsHtml = "\n".join(certParts)
        expiredCount = sum(1 for c in certs if c["status"] == "EXPIRED")
        expiringCount = sum(1 for c in certs if c["status"] in ("EXPIRING_SOON", "CHECK"))
        userCount = sum(1 for c in certs if c["status"] == "USER_CERT")
        validCount = sum(1 for c in certs if c["status"] == "VALID")

    certTableHtml = (
        f'<div class="category-section cert-section" id="cert_section">'
        f'  <div class="cat-header" onclick="toggleCat(\'cert_section\')">'
        f'    <div class="cat-title">'
        f'      <span class="toggle-arrow">▶</span>'
        f'      <span class="cat-name"> Trusted Certificate Policy Audit</span>'
        f'      <span class="cat-count">({len(certs) if certs else 0} certificates)</span>'
        f'    </div>'
        f'    <div class="cat-badges">'
        f'      <span class="badge critical">{expiredCount} Expired</span>'
        f'      <span class="badge warning">{expiringCount} Expiring</span>'
        f'      <span class="badge critical">{userCount} User Installed</span>'
        f'      <span class="badge safe">{validCount} Valid</span>'
        f'    </div>'
        f'  </div>'
        f'  <div class="cat-body">'
        f'    <div class="cert-table-wrap">'
        f'      <table class="cert-table">'
        f'        <thead><tr>'
        f'          <th>Common Name (CN)</th><th>Valid From</th><th>Valid Until</th>'
        f'          <th>Days Old</th><th>Days to Expiry</th><th>Status</th>'
        f'        </tr></thead>'
        f'        <tbody>'
        f'          {certRowsHtml if certs else "<tr><td colspan=6 class=empty-note>No certificates parsed.</td></tr>"}'
        f'        </tbody>'
        f'      </table>'
        f'    </div>'
        f'  </div>'
        f'</div>'
    )

    # Group rows by category
    categories = {}
    for r in rows:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = {"rows": [], "stats": {"CRITICAL": 0, "WARNING": 0, "VERIFY": 0, "SAFE": 0, "INFO": 0, "SKIPPED": 0}}
        categories[cat]["rows"].append(r)
        st = r["status"]
        if st in categories[cat]["stats"]:
            categories[cat]["stats"][st] += 1
        else:
            categories[cat]["stats"]["INFO"] += 1

    # Build category sections
    categorySections = []
    for catIdx, (catName, catData) in enumerate(sorted(categories.items())):
        stats = catData["stats"]
        catRows = catData["rows"]

        badges = []
        for key, cls in [("CRITICAL", "critical"), ("WARNING", "warning"), ("VERIFY", "verify"),
                         ("SAFE", "safe"), ("INFO", "info"), ("SKIPPED", "skipped")]:
            if stats[key] > 0:
                badges.append(f'<span class="badge {cls}">{stats[key]} {key.title()}</span>')
        badgesHtml = " ".join(badges)

        itemsHtml = []
        for r in catRows:
            cmdEsc = htmlEscape(r["command"])
            resEsc = htmlEscape(r["result"])
            descEsc = htmlEscape(r["description"])
            labelEsc = htmlEscape(r["label"])
            st = r["status"]
            cssClass = {"SAFE": "safe", "WARNING": "warning", "CRITICAL": "critical",
                        "VERIFY": "verify", "SKIPPED": "skipped"}.get(st, "info")

            remediationHtml = ""
            remText = r.get("remediation", "")
            if remText and st not in ("SAFE", "INFO"):
                remediationHtml = (
                    f'\n            <div class="detail-group remediation-group">'
                    f'\n              <span class="detail-tag remediation-tag">Remediation</span>'
                    f'\n              <p class="remediation-text">{htmlEscape(remText)}</p>'
                    f'\n            </div>'
                )

            itemsHtml.append(f'''
        <div class="check-item {cssClass}" data-status="{st}" data-search="{htmlEscape(r['label'].lower())} {htmlEscape(r['description'].lower())}">
          <div class="check-head">
            <span class="check-label">{labelEsc}</span>
            <span class="status-pill {cssClass}">{st}</span>
          </div>
          <p class="check-desc">{descEsc}</p>
          <div class="check-detail">
            <div class="detail-group">
              <span class="detail-tag">Command</span>
              <pre><code>{cmdEsc}</code></pre>
            </div>
            <div class="detail-group">
              <span class="detail-tag">Output</span>
              <pre><code>{resEsc if resEsc else "(empty)"}</code></pre>
            </div>{remediationHtml}
          </div>
        </div>''')

        itemsJoined = "\n".join(itemsHtml)
        categorySections.append(f'''
    <div class="category-section" id="cat_{catIdx}">
      <div class="cat-header" onclick="toggleCat('cat_{catIdx}')">
        <div class="cat-title">
          <span class="toggle-arrow">▶</span>
          <span class="cat-name">{htmlEscape(catName)}</span>
          <span class="cat-count">({len(catRows)} checks)</span>
        </div>
        <div class="cat-badges">{badgesHtml}</div>
      </div>
      <div class="cat-body">{itemsJoined}</div>
    </div>''')

    categoriesHtml = "\n".join(categorySections)

    # Device info
    deviceItems = []
    for key, label in [("model", "Model"), ("brand", "Brand"), ("manufacturer", "Manufacturer"),
                       ("android_version", "Android"), ("sdk_level", "SDK"), ("build_id", "Build"),
                       ("serialno", "Serial"), ("soc_model", "SoC")]:
        val = deviceInfo.get(key, "")
        if val and val != "(unknown)":
            deviceItems.append(f'<div class="dev-item"><span class="dev-label">{label}</span><span class="dev-value">{htmlEscape(val)}</span></div>')
    deviceHtml = "\n".join(deviceItems)

    totalChecks = len(rows)

    # ━━━ FULL HTML DOCUMENT ━━━
    _tmplPath = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", "report.html")
    with open(_tmplPath, "r", encoding="utf-8") as _f:
        _tmpl = Template(_f.read())

    doc = _tmpl.safe_substitute(
        VERSION=__version__,
        COUNT_CRITICAL=counts.get("critical", 0),
        COUNT_WARNING=counts.get("warning", 0),
        COUNT_VERIFY=counts.get("verify", 0),
        COUNT_SAFE=counts.get("safe", 0),
        COUNT_INFO=counts.get("info", 0),
        COUNT_SKIPPED=counts.get("skipped", 0),
        TOTAL_CHECKS=totalChecks,
        DEVICE_HTML=deviceHtml,
        CERT_TABLE_HTML=certTableHtml,
        CATEGORIES_HTML=categoriesHtml,
        TIMESTAMP=time.strftime("%Y-%m-%d %H:%M:%S"),
    )

    with open(htmlPath, "w", encoding="utf-8") as f:
        f.write(doc)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLI BANNER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def printBanner(idLine: Optional[str], checkCount: int = 0, categoryCount: int = 0) -> None:
    """Print the ASCII art banner with terminal colours."""
    checksStr = f"[{checkCount} Checks]" if checkCount else "[--- Checks]"
    catsStr = f"[{categoryCount} Categories]" if categoryCount else "[--- Categories]"
    print(f"""
{Colors.BRIGHT_CYAN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  {Colors.BRIGHT_WHITE}██   ██  █████  ██████  ██████   █████  ██   ██{Colors.BRIGHT_CYAN}                  ┃
┃  {Colors.BRIGHT_WHITE}██   ██ ██   ██ ██   ██ ██   ██ ██   ██  ██ ██{Colors.BRIGHT_CYAN}                   ┃
┃  {Colors.BRIGHT_WHITE}███████ ███████ ██████  ██   ██ ███████   ███{Colors.BRIGHT_CYAN}                    ┃
┃  {Colors.BRIGHT_WHITE}██   ██ ██   ██ ██   ██ ██   ██ ██   ██  ██ ██{Colors.BRIGHT_CYAN}                   ┃
┃  {Colors.BRIGHT_WHITE}██   ██ ██   ██ ██   ██ ██████  ██   ██ ██   ██{Colors.BRIGHT_CYAN}                  ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃  {Colors.BOLD}Hardening Audit eXaminer{Colors.RESET}{Colors.BRIGHT_CYAN} v{__version__}                                    ┃
┃  {Colors.DIM}Android OS based Connected Devices Security Configuration Auditor{Colors.BRIGHT_CYAN}┃
┃  {Colors.YELLOW}{checksStr}{Colors.RESET} {Colors.GREEN}{catsStr}{Colors.BRIGHT_CYAN}{' ' * max(1, 53 - _vlen(checksStr) - _vlen(catsStr))}           ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{Colors.RESET}
""")
    if idLine:
        print(f"{Colors.BRIGHT_WHITE}📱 Target Device: {Colors.BOLD}{Colors.BRIGHT_CYAN}{idLine}{Colors.RESET}\n")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MAIN ENTRY POINT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main():
    ap = argparse.ArgumentParser(
        description="HARDAX - Hardening Audit eXaminer for Android OS based Connected Devices",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --json-dir ./commands
  %(prog)s --json-dir ./commands --serial DEVICE123
  %(prog)s --mode ssh --host 192.168.1.100 --ssh-user root --ssh-pass password
  %(prog)s --mode uart --uart-port /dev/ttyUSB0
  %(prog)s --mode uart --uart-port /dev/ttyUSB0 --baud 115200
        """,
    )
    ap.add_argument("--version", action="version", version=f"HARDAX v{__version__}")
    ap.add_argument("--mode", choices=["adb", "ssh", "uart"], default="adb", help="Connection mode (default: adb)")
    ap.add_argument("--json", help="Path to a single commands JSON file")
    ap.add_argument("--json-dir", help="Folder containing *.json check files to merge")
    ap.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL", ""), help="ADB device serial")
    ap.add_argument("--host", help="SSH hostname/IP")
    ap.add_argument("--port", type=int, default=22, help="SSH port (or overridden by UART)")
    ap.add_argument("--ssh-user", help="SSH username")
    ap.add_argument("--ssh-pass", help="SSH password")
    ap.add_argument("--uart-port", help="UART serial port (e.g. /dev/ttyUSB0, /dev/ttyS0, COM3)")
    ap.add_argument("--baud", type=int, default=0, help="UART baud rate (0 = auto-detect, common: 115200, 9600)")
    ap.add_argument("--out", default="hardax_output", help="Output directory")
    ap.add_argument("--progress-numbers", action="store_true", help="Show numeric progress counter")
    ap.add_argument("--show-commands", action="store_true", help="Print each command as it runs")
    ap.add_argument("--skip-certs", action="store_true", help="Skip certificate audit")
    ap.add_argument("--category", default="",
                    help="Comma-separated category names to include (case-insensitive, e.g. SYSTEM,NETWORK)")
    ap.add_argument("--severity", default="",
                    help="Comma-separated levels to include: info,warning,critical")
    ap.add_argument("--json-out", action="store_true",
                    help="Also write a machine-readable JSON report alongside TXT/CSV/HTML")
    ap.add_argument("--exit-code", action="store_true",
                    help="Set process exit code by findings: 0=clean, 1=warning, 2=critical")

    args = ap.parse_args()

    # Auto-detect commands/ directory
    if not args.json and not args.json_dir:
        scriptDir = os.path.dirname(os.path.abspath(__file__))
        defaultCmdDir = os.path.join(scriptDir, "commands")
        if os.path.isdir(defaultCmdDir):
            args.json_dir = defaultCmdDir

    # Load checks
    checks = loadChecks(args.json, args.json_dir)

    # Optional filters: --category and --severity
    if args.category:
        wanted = {c.strip().lower() for c in args.category.split(",") if c.strip()}
        before = len(checks)
        checks = [c for c in checks if c.get("category", "").lower() in wanted]
        print(f"{Colors.BRIGHT_CYAN}⟳ Category filter: {before} → {len(checks)} checks{Colors.RESET}")
    if args.severity:
        wanted = {s.strip().lower() for s in args.severity.split(",") if s.strip()}
        before = len(checks)
        checks = [c for c in checks if c.get("level", "").lower() in wanted]
        print(f"{Colors.BRIGHT_CYAN}⟳ Severity filter: {before} → {len(checks)} checks{Colors.RESET}")
    if not checks:
        print("ERROR: No checks remain after filtering.", file=sys.stderr)
        sys.exit(1)

    # Build device connection
    device: Device
    if args.mode == "adb":
        if which("adb") is None:
            print("ERROR: 'adb' not found in PATH.", file=sys.stderr)
            sys.exit(1)
        runLocal(["adb", "start-server"])

        serial = (args.serial or "").strip() or None
        serial = pickDefaultSerial(serial)
        if not serial:
            explainAdbDevicesAndExit(exitCode=2)

        adbDev = AdbDevice(serial)
        try:
            adbDev.checkConnected()
        except RuntimeError as e:
            print(str(e), file=sys.stderr)
            explainAdbDevicesAndExit(exitCode=3)
        device = adbDev

    elif args.mode == "ssh":
        missing = []
        if not args.host:
            missing.append("--host")
        if not args.ssh_user:
            missing.append("--ssh-user")
        if missing:
            print("ERROR: For --mode ssh you must provide: " + ", ".join(missing), file=sys.stderr)
            sys.exit(1)
        ssh_pass = (
            args.ssh_pass
            or os.environ.get("HARDAX_SSH_PASS")
            or getpass.getpass(f"SSH password for {args.ssh_user}@{args.host}: ")
        )
        device = SshDevice(args.host, args.port, args.ssh_user, ssh_pass)

    else:  # uart
        if not args.uart_port:
            print("ERROR: For --mode uart you must provide --uart-port (e.g. /dev/ttyUSB0)", file=sys.stderr)
            sys.exit(1)
        device = UartDevice(args.uart_port, args.baud)

    # Banner (dynamic counts)
    _catSet = {c.get("category", "General") for c in checks}
    printBanner(device.idString(), checkCount=len(checks), categoryCount=len(_catSet))

    # Progress callback
    def _progress(idx: int, total: int):
        if args.progress_numbers:
            sys.stdout.write("\r" + f"{idx}/{total}")
            sys.stdout.flush()

    # Output paths
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    txtDir = os.path.join(args.out, f"txt_report_{timestamp}")
    htmlDir = os.path.join(args.out, f"html_report_{timestamp}")
    os.makedirs(txtDir, exist_ok=True)
    os.makedirs(htmlDir, exist_ok=True)
    txtFile = os.path.join(txtDir, "audit_report.txt")
    htmlFile = os.path.join(htmlDir, "audit_report.html")
    csvFile = os.path.join(htmlDir, "audit_report.csv")
    jsonFile = os.path.join(htmlDir, "audit_report.json") if args.json_out else None

    # Root detection
    print(f"\n{Colors.BRIGHT_CYAN}🔍 Starting security audit with {len(checks)} checks...{Colors.RESET}\n")

    isRooted, rootMethod = detectRootStatus(device)
    if isRooted:
        if rootMethod in ("ssh-root", "uart-root"):
            print(f"{Colors.GREEN}✓ Root detected ({rootMethod}) - running as root directly, no su needed{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}✓ Root detected ({rootMethod}) - will use su for privileged commands{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}⚠ Device not rooted - some checks may have limited output{Colors.RESET}")
    print()

    # Device info
    deviceInfo = collectDeviceInfo(device)

    # ADB pre-flight
    if isinstance(device, AdbDevice):
        preflight = device.shell("echo HARDAX_PREFLIGHT_OK")
        if "HARDAX_PREFLIGHT_OK" not in preflight:
            print(f"{Colors.BRIGHT_RED}✗ ADB pre-flight check failed!{Colors.RESET}")
            print(f"  Response: {preflight}")
            print(f"  {Colors.YELLOW}Attempting reconnect...{Colors.RESET}")
            runLocal(device.adbArgs() + ["reconnect"])
            time.sleep(3)
            runLocal(device.adbArgs() + ["wait-for-device"], timeout=15)
            time.sleep(2)
            preflight2 = device.shell("echo HARDAX_PREFLIGHT_OK")
            if "HARDAX_PREFLIGHT_OK" not in preflight2:
                print(f"  {Colors.BRIGHT_RED}✗ Device still not responding. Please check:{Colors.RESET}")
                print(f"    • USB cable connected and device unlocked")
                print(f"    • Run: adb kill-server && adb start-server")
                print(f"    • Accept USB debugging prompt on device")
                sys.exit(1)
            print(f"  {Colors.GREEN}✓ Reconnected successfully!{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}✓ ADB connection verified{Colors.RESET}")
        print()

    # SSH pre-flight
    elif isinstance(device, SshDevice):
        preflight = device.shell("echo HARDAX_PREFLIGHT_OK")
        if "HARDAX_PREFLIGHT_OK" not in preflight:
            print(f"{Colors.BRIGHT_RED}✗ SSH pre-flight check failed!{Colors.RESET}")
            print(f"  Response: {preflight!r}")
            print(f"  Check that the SSH server on {device.host}:{device.port} allows command execution.")
            sys.exit(1)
        print(f"{Colors.GREEN}✓ SSH connection verified ({device.host}:{device.port}){Colors.RESET}")

        # Probe shell environment so the user knows what will work
        shellPath   = device.shell("which sh 2>/dev/null || command -v sh 2>/dev/null").strip()
        bashPath    = device.shell("which bash 2>/dev/null || command -v bash 2>/dev/null").strip()
        idOut       = device.shell("id 2>/dev/null").strip()
        unameOut    = device.shell("uname -a 2>/dev/null").strip()
        isAndroid   = bool(device.shell("test -f /system/build.prop && echo YES 2>/dev/null").strip() == "YES")
        hasGetprop  = bool(device.shell("command -v getprop >/dev/null 2>&1 && echo YES").strip() == "YES")
        hasBusybox  = bool(device.shell("command -v busybox >/dev/null 2>&1 && echo YES").strip() == "YES")
        hasToybox   = bool(device.shell("command -v toybox >/dev/null 2>&1 && echo YES").strip() == "YES")
        pathOut     = device.shell("echo $PATH").strip()

        print(f"  Shell     : {shellPath or '(not found)'}"
              + (f"  |  bash: {bashPath}" if bashPath else ""))
        print(f"  Identity  : {idOut or '(unknown)'}")
        print(f"  Kernel    : {unameOut or '(unknown)'}")
        print(f"  PATH      : {pathOut or '(empty)'}")
        tools = []
        if isAndroid:  tools.append("Android/getprop" if hasGetprop else "Android(no getprop)")
        if hasBusybox: tools.append("busybox")
        if hasToybox:  tools.append("toybox")
        if tools:
            print(f"  Tools     : {', '.join(tools)}")
        if not isAndroid:
            print(f"  {Colors.YELLOW}⚠ /system/build.prop not found - device may not be Android."
                  f" Android-specific checks will return empty results.{Colors.RESET}")
        print()

    # UART pre-flight
    elif isinstance(device, UartDevice):
        preflight = device.shell("echo HARDAX_PREFLIGHT_OK")
        if "HARDAX_PREFLIGHT_OK" not in preflight:
            print(f"{Colors.BRIGHT_RED}✗ UART pre-flight check failed!{Colors.RESET}")
            print(f"  Response: {preflight!r}")
            print(f"  {Colors.YELLOW}Check that:{Colors.RESET}")
            print(f"    • UART TX/RX/GND are wired correctly")
            print(f"    • Baud rate is correct (current: {device.baud})")
            print(f"    • The device has a shell on this UART port")
            print(f"    • Try pressing Enter on the serial console first")
            sys.exit(1)
        print(f"{Colors.GREEN}✓ UART connection verified ({device.port} @ {device.baud} baud){Colors.RESET}")

        # Probe shell environment
        uart_info = device.probeShell()

        shellType = "root shell" if uart_info["is_root"] else "user shell"
        print(f"  {Colors.BRIGHT_WHITE}Shell type : {Colors.BOLD}{shellType}{Colors.RESET}")
        print(f"  Shell     : {uart_info['shell'] or '(not found)'}"
              + (f"  |  bash: {uart_info['bash']}" if uart_info["bash"] else ""))
        print(f"  Identity  : {uart_info['uid'] or '(unknown)'}")
        print(f"  Kernel    : {uart_info['uname'] or '(unknown)'}")
        print(f"  PATH      : {uart_info['path'] or '(empty)'}")
        tools = []
        if uart_info["is_android"]:
            tools.append("Android/getprop" if uart_info["has_getprop"] else "Android(no getprop)")
        if uart_info["has_busybox"]: tools.append("busybox")
        if uart_info["has_toybox"]:  tools.append("toybox")
        if tools:
            print(f"  Tools     : {', '.join(tools)}")

        if uart_info["is_root"]:
            print(f"  {Colors.BRIGHT_RED}⚠ UART drops directly into ROOT shell - no authentication!{Colors.RESET}")
        if not uart_info["is_android"]:
            print(f"  {Colors.YELLOW}⚠ /system/build.prop not found - device may not be Android."
                  f" Android-specific checks will return empty results.{Colors.RESET}")
        print()

    # Set up HUD dashboard (only in default mode, not --show-commands)
    global _active_dashboard
    _hud = None
    useShowCommands = args.show_commands

    if not useShowCommands and sys.stdout.isatty():
        # HUD Tactical dashboard mode
        signal.signal(signal.SIGINT, _signalHandler)
        _hud = HUDDashboard(checks, deviceInfo=device.idString())
        _active_dashboard = _hud

    # Run all checks
    rows, counts = runChecks(
        device, checks,
        onProgress=_progress,
        showCommands=useShowCommands,
        isRooted=isRooted,
        rootMethod=rootMethod,
        dashboard=_hud,
    )

    if _hud:
        _hud.finish()
        _active_dashboard = None

    if args.progress_numbers:
        print()

    # Certificate audit
    # Works over both ADB and SSH - cert paths (/system/etc/security/cacerts, etc.)
    # are filesystem-level reads that the shell can perform on any Android device.
    certs = []
    if not args.skip_certs:
        certs = auditCertificates(device)

    # Generate reports
    writeTxtReport(txtFile, deviceInfo, rows, counts, certs, device.idString())
    writeCsvReport(csvFile, rows)
    writeHtmlReport(htmlFile, deviceInfo, rows, counts, certs)
    if jsonFile:
        writeJsonReport(jsonFile, deviceInfo, rows, counts, certs, device.idString())

    # Close SSH / UART if used
    if isinstance(device, (SshDevice, UartDevice)):
        device.close()

    # Summary panel
    total_checks = sum(counts.values())

    # ── Visual‑width helpers (ANSI safe) ─────────────────────────────────
    def _lpad_vis(s: str, width: int) -> str:
        need = width - _vlen(s)
        return s if need <= 0 else (' ' * need) + s

    # ── Box geometry + safe printers ─────────────────────────────────────
    C = Colors.BRIGHT_CYAN
    R = Colors.RESET
    B = Colors.BOLD
    D = Colors.DIM

    FRAME_WIDTH = 68       # number of '═' between corners (kept as-is)
    INNER_WIDTH = FRAME_WIDTH  # inner content width between the two ║

    def _box_top():
        print(f"\n{C}  ╔{'═' * FRAME_WIDTH}╗{R}")
    def _box_sep():
        print(f"{C}  ╠{'═' * FRAME_WIDTH}╣{R}")

    def _box_bottom():
        print(f"{C}  ╚{'═' * FRAME_WIDTH}╝{R}\n")
    def _box_line(content: str):
        print(f"{C}  ║{R}{_vpad(content, INNER_WIDTH)}{C}║{R}")

    # ── Fixed-width progress bar (exact visual width) ────────────────────
    def _bar_fixed(n: int, tot: int, width: int = 16, col: str = Colors.GREEN) -> str:
        filled = int(round((n / tot) * width)) if tot else 0
        filled = max(0, min(width, filled))
        filled_seg = f"{col}{'█' * filled}{R}" if filled else ""
        empty_seg  = f"{D}{'░' * (width - filled)}{R}" if width - filled > 0 else ""
        bar = filled_seg + empty_seg
        return _vpad(bar, width)

    # ── Header lines (left title + right checks) ─────────────────────────
    title_left  = f"  {B}{Colors.BRIGHT_WHITE}HARDAX  AUDIT COMPLETE{R}"
    title_right = f"{D}{total_checks} checks{R}"

    used = _vlen(title_left) + _vlen(title_right)
    mid_spaces = max(0, INNER_WIDTH - used)
    _box_top()
    _box_line(title_left + (" " * mid_spaces) + title_right)

    # target line
    target_line = f"  {D}target{R}  {Colors.BRIGHT_WHITE}{device.idString()}{R}"
    _box_line(target_line)

    _box_sep()

    # ── Summary rows: exact column plan ──────────────────────────────────
    # Layout (visual widths):
    #   2 spaces + sym(1) + space(1) + label(8 L) + 2 + count(4 R) + 2 + pct(6 R) + 2 + bar(16)
    def _summary_row(col, sym, lbl, cnt, tot):
        pct = f"{(cnt / tot * 100):5.1f}%" if tot else "  0.0%"
        bar = _bar_fixed(cnt, tot, width=16, col=col)

        part1 = "  " + f"{col}{sym}{R}" + " "
        part2 = _vpad(f"{col}{lbl}{R}", 8)
        part3 = "  " + _lpad_vis(f"{B}{col}{cnt}{R}", 4)
        part4 = "  " + _lpad_vis(pct, 6)
        part5 = "  " + _vpad(bar, 16)

        _box_line(part1 + part2 + part3 + part4 + part5)

    summaryRows = [
        (Colors.BRIGHT_RED,     '✗', 'CRITICAL', counts['critical']),
        (Colors.YELLOW,         '⚠', 'WARNING',  counts['warning']),
        (Colors.BRIGHT_MAGENTA, '?', 'VERIFY',   counts['verify']),
        (Colors.GREEN,          '✓', 'SAFE',     counts['safe']),
        (Colors.CYAN,           'ℹ', 'INFO',     counts['info']),
    ]
    if counts.get('skipped', 0):
        summaryRows.append((D, '⊘', 'SKIPPED', counts['skipped']))

    for col, sym, lbl, cnt in summaryRows:
        _summary_row(col, sym, lbl, cnt, total_checks)

    _box_sep()

    # footer file paths
    _box_line(f"  {D}TXT {R}  {D}{txtFile}{R}")
    _box_line(f"  {D}HTML{R}  {D}{htmlFile}{R}")
    _box_line(f"  {D}CSV {R}  {D}{csvFile}{R}")
    if jsonFile:
        _box_line(f"  {D}JSON{R}  {D}{jsonFile}{R}")

    _box_bottom()

    # Opt-in: map findings to process exit code for CI integration.
    # 0 = clean (no critical, no warning), 1 = warnings only, 2 = critical present.
    # Off by default to avoid breaking existing scripts that rely on exit 0.
    if args.exit_code:
        if counts.get("critical", 0) > 0:
            sys.exit(2)
        if counts.get("warning", 0) > 0:
            sys.exit(1)
        sys.exit(0)

if __name__ == "__main__":
    main()
