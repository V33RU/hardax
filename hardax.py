#!/usr/bin/env python3
"""
HARDAX — Hardening Audit eXaminer
Android OS based Connected Devices Security Configuration Auditor

488 Security Checks | 18 Categories | 3 Report Formats
Author : Mr-IoT (IOTSRG)
License: MIT
"""

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  IMPORTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import argparse
import base64
import csv
import html
import json
import os
import re
import shutil
import subprocess
import sys
import time
import tempfile
from datetime import datetime
from typing import List, Dict, Any, Tuple, Optional

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  VERSION & CONSTANTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

__version__ = "1.3.0"

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
    "error: closed",
    "adb: error:",
]

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLI ARGV SHIM — strip extra flags before argparse
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
#  GENERAL UTILITIES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def which(prog: str) -> Optional[str]:
    return shutil.which(prog)


def runLocal(cmd: List[str], timeout: int = None) -> Tuple[int, str, str]:
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
    return html.escape(s, quote=False)


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


def isAdbTransportError(output: str) -> bool:
    """Return True when *output* looks like an ADB transport / connection error."""
    if not output:
        return False
    lower = output.lower().strip()
    if len(lower) > 300:
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
    """Abstract shell runner — subclass for ADB or SSH."""
    def shell(self, command: str) -> str:
        raise NotImplementedError()

    def idString(self) -> str:
        raise NotImplementedError()


class AdbDevice(Device):
    """Execute commands on an Android device through ADB."""

    def __init__(self, serial: Optional[str]):
        self.serial = serial

    def _base(self) -> List[str]:
        return ["adb"] + (["-s", self.serial] if self.serial else [])

    def checkConnected(self) -> None:
        code, _, _ = runLocal(self._base() + ["get-state"])
        if code != 0:
            _, devs, _ = runLocal(["adb", "devices", "-l"])
            raise RuntimeError("No ADB device detected or unauthorized. Output:\n" + devs)

    def shell(self, command: str) -> str:
        code, out, err = runLocal(self._base() + ["shell", command])
        txt = (out or "") + (("\n" + err) if err else "")
        txt = txt.replace("\r", "").strip()

        if isAdbTransportError(txt):
            runLocal(self._base() + ["reconnect"])
            time.sleep(2)
            runLocal(self._base() + ["wait-for-device"], timeout=10)
            time.sleep(1)
            code2, out2, err2 = runLocal(self._base() + ["shell", command])
            txt2 = (out2 or "") + (("\n" + err2) if err2 else "")
            return txt2.replace("\r", "").strip()
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
        self.client.set_missing_host_key_policy(self.paramiko.AutoAddPolicy())
        try:
            self.client.connect(hostname=host, port=port, username=user,
                                password=password, look_for_keys=False,
                                allow_agent=False, timeout=20)
        except Exception as e:
            print(f"ERROR: SSH connection failed: {e}", file=sys.stderr)
            sys.exit(1)

    def shell(self, command: str) -> str:
        try:
            stdin, stdout, stderr = self.client.exec_command(command)
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
            mflags = re.search(r"(^|\s)-([iEvFv]+)", st)
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

    if tailN is not None and tailN >= 0:
        filtered = filtered[-tailN:]
    if headN is not None and headN >= 0:
        filtered = filtered[:headN]

    return "\n".join(filtered)


def executeWithFallback(device: Device, command: str,
                        showCommands: bool = False,
                        isRooted: bool = None) -> str:
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

    for block in blocks:
        baseCmd, pipeline = splitPipeline(block)

        candidates = []
        if isRooted or isRooted is None:
            candidates.append('su -c "%s"' % baseCmd)
        candidates.append(baseCmd)

        noP = dropPidFlag(baseCmd)
        if noP != baseCmd:
            if isRooted or isRooted is None:
                candidates.append('su -c "%s"' % noP)
            candidates.append(noP)

        swapped = swapTool(baseCmd)
        if swapped:
            if isRooted or isRooted is None:
                candidates.append('su -c "%s"' % swapped)
            candidates.append(swapped)
            swappedNoP = dropPidFlag(swapped)
            if swappedNoP != swapped:
                if isRooted or isRooted is None:
                    candidates.append('su -c "%s"' % swappedNoP)
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
        adbd-root | magisk | su | su-present-not-working | none
    """

    # 1. Try ADBD root (eng / userdebug builds)
    try:
        if isinstance(device, AdbDevice):
            runLocal(["adb", "start-server"])
            runLocal(device._base() + ["root"])
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
        if hasTimeout:
            return device.shell(f"timeout {seconds} su -c '{cmd}' 2>/dev/null")
        return device.shell(f"su -c '{cmd}' 2>/dev/null")

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
            return f"{v} (from {p})"
    return "(unknown)"


def _getPropWithCpuinfo(device: Device, props: List[str]) -> str:
    for p in props:
        v = device.shell(f"getprop {p}").strip()
        if v:
            return f"{v} (from {p})"
    cpuinfo = device.shell("cat /proc/cpuinfo")
    m = re.search(r"(?i)hardware\s*:\s*(.+)", cpuinfo)
    if m:
        return m.group(1).strip() + " (from /proc/cpuinfo)"
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

    def clean(x: str) -> str:
        i = x.rfind(" (from ")
        return x[:i] if i != -1 else x

    return {
        "model": clean(model),
        "brand": clean(brand),
        "manufacturer": clean(manufacturer),
        "name": clean(name),
        "soc_manufacturer": clean(socManufacturer),
        "soc_model": clean(socModel),
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
        "permission denied", "unknown", "invalid", "failed",
        "inaccessible", "cmd: can't find", "not supported",
        "service not found", "does not exist", "no output",
    ]
    if lower in ["", "(empty)"]:
        return True
    for indicator in errorIndicators:
        if indicator in lower and len(lower) < 100:
            return True
    return False


def runChecks(device: Device, checks: List[Dict[str, Any]],
              onProgress=None, showCommands: bool = False,
              isRooted: bool = False) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    """
    Execute every check against the device and classify the result.
    Returns (rows, counts) where rows is the full audit data.
    """
    rows: List[Dict[str, Any]] = []
    counts = {"safe": 0, "warning": 0, "critical": 0, "info": 0, "verify": 0, "skipped": 0}
    total = len(checks)
    startTime = time.time()
    consecutiveAdbErrors = 0

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

        raw = executeWithFallback(device, command, showCommands, isRooted=isRooted) if command else ""

        # ── ADB transport error → SKIPPED ──
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
                    runLocal(device._base() + ["reconnect"])
                    time.sleep(3)
                    runLocal(device._base() + ["wait-for-device"], timeout=15)
                    time.sleep(2)
                    testCode, testOut, _ = runLocal(device._base() + ["shell", "echo HARDAX_ALIVE"], timeout=5)
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
                            "description": desc + " [⊘ Skipped — ADB connection lost]",
                            "needs_verification": False,
                        })
                        for remainingChk in checks[idx:]:
                            rows.append({
                                "category": remainingChk.get("category", "General"),
                                "label": remainingChk.get("label", "Unnamed"),
                                "command": remainingChk.get("command", ""),
                                "result": "[SKIPPED] Device offline — ADB connection lost",
                                "status": "SKIPPED",
                                "description": remainingChk.get("description", ""),
                            })
                            counts["skipped"] += 1
                        break
        else:
            consecutiveAdbErrors = 0
            normalized = normalizeForMatch(raw)
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

            # ── Determine status ──
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

        # ── Progress display ──
        if onProgress or showCommands:
            try:
                elapsed = time.time() - startTime
                avgTime = elapsed / idx if idx > 0 else 0
                remaining = int(avgTime * (total - idx))
                etaStr = f"{remaining // 60}m {remaining % 60}s" if remaining > 60 else f"{remaining}s"
                percentage = (idx / total) * 100

                statusColor = {
                    "SAFE": Colors.GREEN,
                    "CRITICAL": Colors.BRIGHT_RED,
                    "WARNING": Colors.YELLOW,
                    "VERIFY": Colors.BRIGHT_MAGENTA,
                    "SKIPPED": Colors.DIM,
                }.get(status, Colors.CYAN)
                statusSymbol = {
                    "SAFE": "✓", "CRITICAL": "✗", "WARNING": "⚠",
                    "VERIFY": "?", "SKIPPED": "⊘",
                }.get(status, "ℹ")

                barWidth = 30
                filled = int((idx / total) * barWidth)
                bar = "█" * filled + "░" * (barWidth - filled)

                print(
                    f"\r{Colors.CYAN}[{idx:3d}/{total:3d}]{Colors.RESET} "
                    f"{Colors.BRIGHT_BLUE}[{bar}]{Colors.RESET} "
                    f"{Colors.BRIGHT_WHITE}{percentage:5.1f}%{Colors.RESET} "
                    f"{Colors.DIM}ETA: {etaStr}{Colors.RESET}",
                    end="", flush=True,
                )

                if showCommands:
                    print()
                    labelDisplay = label[:50] + "..." if len(label) > 50 else label
                    print(
                        f"  {Colors.BRIGHT_CYAN}▶{Colors.RESET} {Colors.BOLD}{labelDisplay}{Colors.RESET} "
                        f"{statusColor}[{statusSymbol} {status}]{Colors.RESET}"
                    )
                    cmdDisplay = command[:70] + "..." if len(command) > 70 else command
                    print(f"    {Colors.DIM}$ {cmdDisplay}{Colors.RESET}", flush=True)

                if onProgress:
                    onProgress(idx, total)
            except Exception:
                pass

        # ── Build row ──
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
        })

    print()
    return rows, counts


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CERTIFICATE AUDIT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _findCertFiles(device: Device) -> List[str]:
    """Search standard Android CA directories for certificate files."""
    candidates = [
        "/system/etc/security/cacerts",
        "/system/etc/security/cacerts_google",
        "/apex/com.android.conscrypt/cacerts",
        "/apex/com.android.conscrypt/etc/security/cacerts",
    ]
    files = []
    for base in candidates:
        listing = device.shell(f"ls -1 {base} 2>/dev/null")
        names = [n.strip() for n in (listing.splitlines() if listing else []) if n.strip()]
        matched = []
        for n in names:
            if n.endswith(".0") or re.fullmatch(r"[0-9a-fA-F]{1,8}", n):
                matched.append(f"{base}/{n}")
        files.extend(matched)
        if CERT_DEBUG:
            print(f"[cert-debug] {base}: {len(matched)} files matched")
    return files


def _readCertBytes(device: Device, path: str):
    """Read certificate bytes from device, trying PEM first then DER via base64."""
    txt = device.shell(f"cat {path} 2>/dev/null")
    if txt and "-----BEGIN CERTIFICATE-----" in txt:
        return txt.encode("utf-8"), "PEM"
    b64 = device.shell(f"base64 {path} 2>/dev/null")
    if b64 and "not found" not in b64.lower() and b64.strip():
        try:
            cleaned = "".join(b64.strip().split())
            return base64.b64decode(cleaned, validate=False), "DER"
        except Exception:
            return None, None
    return None, None


def auditCertificates(device: Device) -> List[Dict[str, Any]]:
    """Pull and analyze system + user certificates from the device."""
    certs: List[Dict[str, Any]] = []
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

    for i, certPath in enumerate(certFiles[:CERT_LIMIT]):
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
                notBefore = getattr(cert, "not_valid_before")
                notAfter = getattr(cert, "not_valid_after")
            except Exception:
                notBefore = getattr(cert, "not_valid_before_utc", None)
                notAfter = getattr(cert, "not_valid_after_utc", None)
            if notBefore is None or notAfter is None:
                continue

            try:
                subjectStr = subject.rfc4514_string() if subject else "Unknown"
                issuerStr = issuer.rfc4514_string() if issuer else "Unknown"
            except Exception:
                subjectStr = "Unknown"
                issuerStr = "Unknown"

            daysOld = (today - notBefore.replace(tzinfo=None)).days
            daysUntilExpiry = (notAfter.replace(tzinfo=None) - today).days

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
                "not_before": notBefore.strftime("%Y-%m-%d"),
                "not_after": notAfter.strftime("%Y-%m-%d"),
                "days_old": daysOld,
                "days_until_expiry": daysUntilExpiry,
                "status": status,
                "risk": risk,
            })
        except Exception:
            continue

    # User-installed certs across all profiles
    try:
        userRoots = device.shell("ls -d /data/misc/user/*/cacerts-added 2>/dev/null")
        userDirs = [d.strip() for d in (userRoots.split("\n") if userRoots else []) if d.strip()]
        if not userDirs:
            userDirs = ["/data/misc/user/0/cacerts-added"]
        for d in userDirs:
            ulist = device.shell(f"ls -1 {d} 2>/dev/null")
            if ulist.strip():
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

    return sorted(certs, key=lambda x: (x["risk"] != "critical", x["risk"] != "warning", x["days_until_expiry"]))



# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  REPORT GENERATION — TXT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def writeTxtReport(path: str, deviceInfo: Dict[str, str],
                   rows: List[Dict[str, Any]], counts: Dict[str, int],
                   certs: List[Dict[str, Any]], deviceIdStr: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(f"HARDAX — Hardening Audit eXaminer Report\nGenerated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("Device Information\n" + "=" * 40 + "\n")
        for k in ["model", "brand", "manufacturer", "name", "soc_manufacturer", "soc_model",
                   "android_version", "sdk_level", "build_id", "fingerprint", "serialno", "timezone"]:
            f.write(f"{k.replace('_', ' ').title()}: {deviceInfo.get(k, '')}\n")

        if certs:
            f.write("\n" + "=" * 40 + "\nCertificate Audit\n" + "=" * 40 + "\n")
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
#  REPORT GENERATION — CSV
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def writeCsvReport(path: str, rows: List[Dict[str, Any]]) -> None:
    fieldnames = ["timestamp", "category", "label", "level", "bucket", "status",
                  "matched", "command", "result", "description"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})



# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  REPORT GENERATION — HTML (Hacker Aesthetic)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def writeHtmlReport(htmlPath: str, deviceInfo: Dict[str, str],
                    rows: List[Dict[str, Any]], counts: Dict[str, int],
                    certs: List[Dict[str, Any]] = None) -> None:
    """Generate an interactive HTML report with hacker aesthetic and severity toggles."""

    # ── Certificate section ──
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
                f'<tr class="cert-row {riskClass}">'
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
        f'      <span class="cat-name">🔐 CERTIFICATE AUDIT</span>'
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

    # ── Group rows by category ──
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

    # ── Build category sections ──
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
            </div>
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

    # ── Device info ──
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
    doc = f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HARDAX — Security Audit Report</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;500;600;700&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {{
      --bg-0: #05080a;
      --bg-1: #0b1018;
      --bg-2: #111a26;
      --bg-3: #182535;
      --text-0: #c9d6e3;
      --text-1: #7a8fa3;
      --border: #1c2e42;
      --accent: #00e5ff;
      --critical: #ff2d55;
      --warning: #ffb300;
      --safe: #00e676;
      --info: #448aff;
      --verify: #ba68c8;
      --skipped: #546e7a;
      --glow-critical: rgba(255,45,85,0.25);
      --glow-safe: rgba(0,230,118,0.15);
    }}

    * {{ box-sizing: border-box; margin: 0; padding: 0; }}

    body {{
      font-family: 'Fira Code', monospace;
      background: var(--bg-0);
      color: var(--text-0);
      line-height: 1.7;
      font-size: 13px;
      font-weight: 400;
    }}

    .container {{ max-width: 1440px; margin: 0 auto; padding: 16px; }}

    /* ── TOOLBAR ── */
    .toolbar {{
      position: sticky;
      top: 0;
      z-index: 1000;
      background: linear-gradient(135deg, #0d1f33 0%, #091420 60%, #0a1018 100%);
      border: 1px solid var(--border);
      border-bottom: 1px solid #00e5ff22;
      padding: 14px 20px;
      border-radius: 0 0 10px 10px;
      margin-bottom: 20px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 10px;
      box-shadow: 0 4px 30px rgba(0,229,255,0.05);
    }}

    .toolbar-brand {{
      display: flex;
      align-items: center;
      gap: 12px;
    }}

    .toolbar-brand h1 {{
      color: var(--accent);
      font-size: 1.3rem;
      font-weight: 700;
      letter-spacing: 2px;
      text-shadow: 0 0 12px rgba(0,229,255,0.4);
    }}

    .version-tag {{
      background: rgba(0,229,255,0.12);
      color: var(--accent);
      padding: 3px 10px;
      border-radius: 4px;
      font-size: 0.7rem;
      font-weight: 600;
      letter-spacing: 1px;
      border: 1px solid rgba(0,229,255,0.2);
    }}

    .toolbar-controls {{
      display: flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }}

    .search-input {{
      background: rgba(0,229,255,0.06);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 14px;
      color: var(--text-0);
      font-family: 'Fira Code', monospace;
      font-size: 0.8rem;
      width: 240px;
      outline: none;
      transition: all 0.2s;
    }}

    .search-input::placeholder {{ color: var(--text-1); }}
    .search-input:focus {{ border-color: var(--accent); box-shadow: 0 0 8px rgba(0,229,255,0.15); }}

    .btn {{
      background: rgba(255,255,255,0.04);
      border: 1px solid var(--border);
      color: var(--text-1);
      padding: 8px 14px;
      border-radius: 6px;
      cursor: pointer;
      font-family: 'Fira Code', monospace;
      font-size: 0.75rem;
      font-weight: 500;
      transition: all 0.2s;
      white-space: nowrap;
    }}

    .btn:hover {{ background: rgba(0,229,255,0.1); color: var(--accent); border-color: var(--accent); }}

    /* ── SEVERITY TOGGLE BAR ── */
    .severity-bar {{
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
      margin-bottom: 18px;
      padding: 12px 16px;
      background: var(--bg-1);
      border-radius: 8px;
      border: 1px solid var(--border);
    }}

    .sev-toggle {{
      padding: 6px 16px;
      border-radius: 4px;
      cursor: pointer;
      font-family: 'Fira Code', monospace;
      font-size: 0.75rem;
      font-weight: 600;
      letter-spacing: 0.5px;
      border: 1px solid transparent;
      transition: all 0.2s;
      user-select: none;
    }}

    .sev-toggle.active {{ opacity: 1; }}
    .sev-toggle.inactive {{ opacity: 0.3; filter: grayscale(0.8); }}

    .sev-toggle[data-sev="CRITICAL"] {{ background: rgba(255,45,85,0.15); color: var(--critical); border-color: rgba(255,45,85,0.3); }}
    .sev-toggle[data-sev="WARNING"]  {{ background: rgba(255,179,0,0.15); color: var(--warning); border-color: rgba(255,179,0,0.3); }}
    .sev-toggle[data-sev="VERIFY"]   {{ background: rgba(186,104,200,0.15); color: var(--verify); border-color: rgba(186,104,200,0.3); }}
    .sev-toggle[data-sev="SAFE"]     {{ background: rgba(0,230,118,0.12); color: var(--safe); border-color: rgba(0,230,118,0.25); }}
    .sev-toggle[data-sev="INFO"]     {{ background: rgba(68,138,255,0.12); color: var(--info); border-color: rgba(68,138,255,0.25); }}
    .sev-toggle[data-sev="SKIPPED"]  {{ background: rgba(84,110,122,0.15); color: var(--skipped); border-color: rgba(84,110,122,0.3); }}

    /* ── SUMMARY CARDS ── */
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
      gap: 12px;
      margin-bottom: 20px;
    }}

    .stat-card {{
      background: var(--bg-1);
      border-radius: 8px;
      padding: 18px 16px;
      border: 1px solid var(--border);
      text-align: center;
      transition: transform 0.15s;
      position: relative;
      overflow: hidden;
    }}

    .stat-card::before {{
      content: "";
      position: absolute;
      top: 0; left: 0; right: 0;
      height: 2px;
    }}

    .stat-card:hover {{ transform: translateY(-2px); }}
    .stat-card.critical::before {{ background: var(--critical); box-shadow: 0 0 12px var(--glow-critical); }}
    .stat-card.warning::before  {{ background: var(--warning); }}
    .stat-card.verify::before   {{ background: var(--verify); }}
    .stat-card.safe::before     {{ background: var(--safe); box-shadow: 0 0 12px var(--glow-safe); }}
    .stat-card.info::before     {{ background: var(--info); }}
    .stat-card.skipped::before  {{ background: var(--skipped); }}
    .stat-card.total::before    {{ background: var(--accent); }}

    .stat-card .num {{
      font-size: 2.2rem;
      font-weight: 700;
      line-height: 1;
      margin-bottom: 6px;
    }}

    .stat-card.critical .num {{ color: var(--critical); text-shadow: 0 0 15px var(--glow-critical); }}
    .stat-card.warning .num  {{ color: var(--warning); }}
    .stat-card.verify .num   {{ color: var(--verify); }}
    .stat-card.safe .num     {{ color: var(--safe); text-shadow: 0 0 10px var(--glow-safe); }}
    .stat-card.info .num     {{ color: var(--info); }}
    .stat-card.skipped .num  {{ color: var(--skipped); }}
    .stat-card.total .num    {{ color: var(--accent); text-shadow: 0 0 10px rgba(0,229,255,0.3); }}

    .stat-card .lbl {{
      color: var(--text-1);
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 1.5px;
    }}

    /* ── DEVICE INFO & CHART ── */
    .info-row {{
      display: grid;
      grid-template-columns: 1fr 280px;
      gap: 16px;
      margin-bottom: 20px;
    }}

    @media (max-width: 900px) {{
      .info-row {{ grid-template-columns: 1fr; }}
    }}

    .dev-card {{
      background: linear-gradient(135deg, #0d2137 0%, #0a1929 100%);
      border-radius: 8px;
      padding: 20px;
      border: 1px solid var(--border);
    }}

    .dev-card h2 {{
      font-size: 0.8rem;
      color: var(--accent);
      margin-bottom: 14px;
      text-transform: uppercase;
      letter-spacing: 2px;
      font-weight: 600;
    }}

    .dev-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 10px;
    }}

    .dev-item {{
      background: rgba(0,229,255,0.04);
      padding: 10px 12px;
      border-radius: 6px;
      border: 1px solid rgba(0,229,255,0.08);
    }}

    .dev-label {{
      display: block;
      font-size: 0.65rem;
      color: var(--text-1);
      margin-bottom: 3px;
      text-transform: uppercase;
      letter-spacing: 1px;
    }}

    .dev-value {{
      font-weight: 600;
      font-size: 0.85rem;
      color: var(--text-0);
    }}

    .chart-card {{
      background: var(--bg-1);
      border-radius: 8px;
      padding: 16px;
      border: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: center;
    }}

    /* ── CATEGORY SECTIONS ── */
    .category-section {{
      background: var(--bg-1);
      border-radius: 8px;
      margin-bottom: 12px;
      border: 1px solid var(--border);
      overflow: hidden;
    }}

    .cat-header {{
      background: var(--bg-2);
      padding: 14px 18px;
      cursor: pointer;
      display: flex;
      justify-content: space-between;
      align-items: center;
      transition: background 0.15s;
      user-select: none;
    }}

    .cat-header:hover {{ background: var(--bg-3); }}

    .cat-title {{
      display: flex;
      align-items: center;
      gap: 10px;
    }}

    .toggle-arrow {{
      font-size: 0.7rem;
      color: var(--text-1);
      transition: transform 0.25s;
    }}

    .category-section.open .toggle-arrow {{ transform: rotate(90deg); }}

    .cat-name {{
      font-weight: 600;
      font-size: 0.85rem;
      text-transform: uppercase;
      letter-spacing: 1.5px;
      color: var(--accent);
    }}

    .cat-count {{
      color: var(--text-1);
      font-size: 0.75rem;
      font-weight: 400;
    }}

    .cat-badges {{
      display: flex;
      gap: 6px;
      flex-wrap: wrap;
    }}

    .badge {{
      padding: 3px 10px;
      border-radius: 4px;
      font-size: 0.65rem;
      font-weight: 600;
      letter-spacing: 0.3px;
    }}

    .badge.critical {{ background: rgba(255,45,85,0.15); color: var(--critical); }}
    .badge.warning  {{ background: rgba(255,179,0,0.12); color: var(--warning); }}
    .badge.verify   {{ background: rgba(186,104,200,0.12); color: var(--verify); }}
    .badge.safe     {{ background: rgba(0,230,118,0.1); color: var(--safe); }}
    .badge.info     {{ background: rgba(68,138,255,0.1); color: var(--info); }}
    .badge.skipped  {{ background: rgba(84,110,122,0.12); color: var(--skipped); }}

    .cat-body {{
      display: none;
      padding: 14px 18px;
    }}

    .category-section.open .cat-body {{ display: block; }}

    /* ── CHECK ITEMS ── */
    .check-item {{
      background: var(--bg-2);
      border-radius: 6px;
      padding: 14px;
      margin-bottom: 10px;
      border-left: 3px solid var(--border);
      transition: border-color 0.15s;
    }}

    .check-item.critical {{ border-left-color: var(--critical); }}
    .check-item.warning  {{ border-left-color: var(--warning); }}
    .check-item.verify   {{ border-left-color: var(--verify); }}
    .check-item.safe     {{ border-left-color: var(--safe); }}
    .check-item.info     {{ border-left-color: var(--info); }}
    .check-item.skipped  {{ border-left-color: var(--skipped); opacity: 0.6; }}
    .check-item:last-child {{ margin-bottom: 0; }}

    .check-head {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 6px;
    }}

    .check-label {{
      font-weight: 600;
      font-size: 0.85rem;
      color: var(--text-0);
    }}

    .status-pill {{
      padding: 2px 10px;
      border-radius: 3px;
      font-size: 0.65rem;
      font-weight: 700;
      letter-spacing: 1px;
    }}

    .status-pill.critical {{ background: var(--critical); color: #fff; }}
    .status-pill.warning  {{ background: var(--warning); color: #000; }}
    .status-pill.verify   {{ background: var(--verify); color: #fff; }}
    .status-pill.safe     {{ background: var(--safe); color: #000; }}
    .status-pill.info     {{ background: var(--info); color: #fff; }}
    .status-pill.skipped  {{ background: var(--skipped); color: #fff; }}

    .check-desc {{
      color: var(--text-1);
      font-size: 0.75rem;
      margin-bottom: 10px;
      font-weight: 400;
    }}

    .detail-group {{ margin-bottom: 8px; }}
    .detail-group:last-child {{ margin-bottom: 0; }}

    .detail-tag {{
      display: inline-block;
      font-size: 0.6rem;
      color: var(--accent);
      margin-bottom: 4px;
      text-transform: uppercase;
      letter-spacing: 1.5px;
      font-weight: 600;
    }}

    pre {{
      background: #060d14;
      color: #00e676;
      padding: 10px 14px;
      border-radius: 4px;
      overflow-x: auto;
      font-size: 0.78rem;
      font-family: 'Fira Code', monospace;
      max-height: 180px;
      white-space: pre-wrap;
      word-break: break-word;
      border: 1px solid #0d1f2d;
    }}

    /* ── CERT TABLE ── */
    .cert-table-wrap {{
      overflow-x: auto;
      border-radius: 6px;
      border: 1px solid var(--border);
    }}

    .cert-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.78rem;
    }}

    .cert-table th {{
      background: var(--bg-3);
      padding: 10px 14px;
      text-align: left;
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.65rem;
      letter-spacing: 1px;
      color: var(--text-1);
      border-bottom: 1px solid var(--border);
    }}

    .cert-table td {{
      padding: 8px 14px;
      border-bottom: 1px solid var(--border);
    }}

    .cert-row:hover {{ background: var(--bg-2); }}
    .cert-row.critical {{ background: rgba(255,45,85,0.05); }}
    .cert-row.warning  {{ background: rgba(255,179,0,0.05); }}

    .mono-right {{ font-variant-numeric: tabular-nums; text-align: right; }}

    .cert-status {{
      padding: 3px 8px;
      border-radius: 3px;
      font-size: 0.65rem;
      font-weight: 600;
      white-space: nowrap;
    }}

    .cert-status.critical {{ background: rgba(255,45,85,0.2); color: var(--critical); }}
    .cert-status.warning  {{ background: rgba(255,179,0,0.15); color: var(--warning); }}
    .cert-status.safe     {{ background: rgba(0,230,118,0.12); color: var(--safe); }}

    .empty-note {{ color: var(--text-1); font-style: italic; }}

    /* ── FOOTER ── */
    footer {{
      text-align: center;
      padding: 24px;
      color: var(--text-1);
      font-size: 0.7rem;
      border-top: 1px solid var(--border);
      margin-top: 32px;
      letter-spacing: 0.5px;
    }}

    footer strong {{ color: var(--accent); }}

    .hidden {{ display: none !important; }}
  </style>
</head>
<body>
  <div class="container">

    <!-- TOOLBAR -->
    <div class="toolbar">
      <div class="toolbar-brand">
        <h1>⟩_ HARDAX</h1>
        <span class="version-tag">v{__version__}</span>
      </div>
      <div class="toolbar-controls">
        <input type="text" class="search-input" id="searchInput" placeholder="search checks...">
        <button class="btn" onclick="expandAll()">+ Expand</button>
        <button class="btn" onclick="collapseAll()">− Collapse</button>
      </div>
    </div>

    <!-- SEVERITY TOGGLE BAR -->
    <div class="severity-bar" id="severityBar">
      <span class="sev-toggle active" data-sev="CRITICAL" onclick="toggleSev(this)">✗ CRITICAL ({counts.get("critical", 0)})</span>
      <span class="sev-toggle active" data-sev="WARNING"  onclick="toggleSev(this)">⚠ WARNING ({counts.get("warning", 0)})</span>
      <span class="sev-toggle active" data-sev="VERIFY"   onclick="toggleSev(this)">? VERIFY ({counts.get("verify", 0)})</span>
      <span class="sev-toggle active" data-sev="SAFE"     onclick="toggleSev(this)">✓ SAFE ({counts.get("safe", 0)})</span>
      <span class="sev-toggle active" data-sev="INFO"     onclick="toggleSev(this)">ℹ INFO ({counts.get("info", 0)})</span>
      <span class="sev-toggle active" data-sev="SKIPPED"  onclick="toggleSev(this)">⊘ SKIPPED ({counts.get("skipped", 0)})</span>
    </div>

    <!-- SUMMARY CARDS -->
    <div class="summary-grid">
      <div class="stat-card critical"><div class="num">{counts.get("critical", 0)}</div><div class="lbl">Critical</div></div>
      <div class="stat-card warning"><div class="num">{counts.get("warning", 0)}</div><div class="lbl">Warnings</div></div>
      <div class="stat-card verify"><div class="num">{counts.get("verify", 0)}</div><div class="lbl">Verify</div></div>
      <div class="stat-card safe"><div class="num">{counts.get("safe", 0)}</div><div class="lbl">Safe</div></div>
      <div class="stat-card info"><div class="num">{counts.get("info", 0)}</div><div class="lbl">Info</div></div>
      <div class="stat-card skipped"><div class="num">{counts.get("skipped", 0)}</div><div class="lbl">Skipped</div></div>
      <div class="stat-card total"><div class="num">{totalChecks}</div><div class="lbl">Total</div></div>
    </div>

    <!-- DEVICE INFO + CHART -->
    <div class="info-row">
      <div class="dev-card">
        <h2>▸ target device</h2>
        <div class="dev-grid">{deviceHtml}</div>
      </div>
      <div class="chart-card">
        <canvas id="summaryChart" width="240" height="240"></canvas>
      </div>
    </div>

    <!-- CERTIFICATES -->
    {certTableHtml}

    <!-- CATEGORIES -->
    <div id="categoriesContainer">
      {categoriesHtml}
    </div>

    <footer>
      <p><strong>HARDAX</strong> — Hardening Audit eXaminer v{__version__} | {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
      <p>Android OS Security Configuration Auditor | IOTSRG</p>
    </footer>
  </div>

  <script>
    /* ── Category toggle ── */
    function toggleCat(id) {{
      document.getElementById(id).classList.toggle('open');
    }}
    function expandAll() {{
      document.querySelectorAll('.category-section').forEach(s => s.classList.add('open'));
    }}
    function collapseAll() {{
      document.querySelectorAll('.category-section').forEach(s => s.classList.remove('open'));
    }}

    /* ── Severity filter toggles ── */
    const activeSev = new Set(['CRITICAL','WARNING','VERIFY','SAFE','INFO','SKIPPED']);

    function toggleSev(el) {{
      const sev = el.getAttribute('data-sev');
      if (activeSev.has(sev)) {{
        activeSev.delete(sev);
        el.classList.remove('active');
        el.classList.add('inactive');
      }} else {{
        activeSev.add(sev);
        el.classList.remove('inactive');
        el.classList.add('active');
      }}
      applySevFilter();
    }}

    function applySevFilter() {{
      document.querySelectorAll('.category-section:not(.cert-section)').forEach(section => {{
        const items = section.querySelectorAll('.check-item');
        let visible = 0;
        items.forEach(item => {{
          const st = item.getAttribute('data-status');
          const show = activeSev.has(st);
          item.classList.toggle('hidden', !show);
          if (show) visible++;
        }});
        section.classList.toggle('hidden', visible === 0);
        if (visible > 0 && !section.classList.contains('open')) {{
          /* keep closed unless user opened */
        }}
      }});
    }}

    /* ── Search ── */
    document.getElementById('searchInput').addEventListener('input', function(e) {{
      const q = e.target.value.toLowerCase().trim();
      document.querySelectorAll('.category-section:not(.cert-section)').forEach(section => {{
        const items = section.querySelectorAll('.check-item');
        let vis = 0;
        items.forEach(item => {{
          const txt = item.getAttribute('data-search') || '';
          const st = item.getAttribute('data-status');
          const matchSearch = !q || txt.includes(q);
          const matchSev = activeSev.has(st);
          const show = matchSearch && matchSev;
          item.classList.toggle('hidden', !show);
          if (show) vis++;
        }});
        section.classList.toggle('hidden', vis === 0);
        if (q && vis > 0) section.classList.add('open');
      }});
    }});

    /* ── Doughnut chart ── */
    window.addEventListener('load', function() {{
      const ctx = document.getElementById('summaryChart').getContext('2d');
      new Chart(ctx, {{
        type: 'doughnut',
        data: {{
          labels: ['Critical','Warning','Verify','Safe','Info','Skipped'],
          datasets: [{{
            data: [{counts.get("critical",0)},{counts.get("warning",0)},{counts.get("verify",0)},{counts.get("safe",0)},{counts.get("info",0)},{counts.get("skipped",0)}],
            backgroundColor: ['#ff2d55','#ffb300','#ba68c8','#00e676','#448aff','#546e7a'],
            borderWidth: 0,
            hoverOffset: 6
          }}]
        }},
        options: {{
          responsive: true,
          cutout: '68%',
          plugins: {{
            legend: {{
              position: 'bottom',
              labels: {{
                padding: 12,
                usePointStyle: true,
                font: {{ family: "'Fira Code', monospace", size: 10 }},
                color: '#7a8fa3'
              }}
            }}
          }}
        }}
      }});
    }});
  </script>
</body>
</html>'''

    with open(htmlPath, "w", encoding="utf-8") as f:
        f.write(doc)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  CLI BANNER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def printBanner(idLine: Optional[str]) -> None:
    """Print the ASCII art banner with terminal colours."""
    print(f"""
{Colors.BRIGHT_CYAN}┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃  {Colors.BRIGHT_WHITE}██   ██  █████  ██████  ██████   █████  ██   ██{Colors.BRIGHT_CYAN}               ┃
┃  {Colors.BRIGHT_WHITE}██   ██ ██   ██ ██   ██ ██   ██ ██   ██  ██ ██{Colors.BRIGHT_CYAN}                ┃
┃  {Colors.BRIGHT_WHITE}███████ ███████ ██████  ██   ██ ███████   ███{Colors.BRIGHT_CYAN}                 ┃
┃  {Colors.BRIGHT_WHITE}██   ██ ██   ██ ██   ██ ██   ██ ██   ██  ██ ██{Colors.BRIGHT_CYAN}                ┃
┃  {Colors.BRIGHT_WHITE}██   ██ ██   ██ ██   ██ ██████  ██   ██ ██   ██{Colors.BRIGHT_CYAN}               ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃  {Colors.BOLD}Hardening Audit eXaminer{Colors.RESET}{Colors.BRIGHT_CYAN} v{__version__}                               ┃
┃  {Colors.DIM}Android OS based IoT Devices Security Configuration Auditor{Colors.BRIGHT_CYAN}   ┃
┃  {Colors.YELLOW}[488 Checks]{Colors.RESET} {Colors.GREEN}[18 Categories]{Colors.BRIGHT_CYAN}                                   ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{Colors.RESET}
""")
    if idLine:
        print(f"{Colors.BRIGHT_WHITE}📱 Target Device: {Colors.BOLD}{Colors.BRIGHT_CYAN}{idLine}{Colors.RESET}\n")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#  MAIN ENTRY POINT
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def main():
    ap = argparse.ArgumentParser(
        description="HARDAX — Hardening Audit eXaminer for Android / IoT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --json-dir ./commands
  %(prog)s --json-dir ./commands --serial DEVICE123
  %(prog)s --mode ssh --host 192.168.1.100 --ssh-user root --ssh-pass password
        """,
    )
    ap.add_argument("--version", action="version", version=f"HARDAX v{__version__}")
    ap.add_argument("--mode", choices=["adb", "ssh"], default="adb", help="Connection mode (default: adb)")
    ap.add_argument("--json", help="Path to a single commands JSON file")
    ap.add_argument("--json-dir", help="Folder containing *.json check files to merge")
    ap.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL", ""), help="ADB device serial")
    ap.add_argument("--host", help="SSH hostname/IP")
    ap.add_argument("--port", type=int, default=22, help="SSH port")
    ap.add_argument("--ssh-user", help="SSH username")
    ap.add_argument("--ssh-pass", help="SSH password")
    ap.add_argument("--out", default="hardax_output", help="Output directory")
    ap.add_argument("--progress-numbers", action="store_true", help="Show numeric progress counter")
    ap.add_argument("--show-commands", action="store_true", help="Print each command as it runs")
    ap.add_argument("--skip-certs", action="store_true", help="Skip certificate audit")

    args = ap.parse_args()

    # ── Auto-detect commands/ directory ──
    if not args.json and not args.json_dir:
        scriptDir = os.path.dirname(os.path.abspath(__file__))
        defaultCmdDir = os.path.join(scriptDir, "commands")
        if os.path.isdir(defaultCmdDir):
            args.json_dir = defaultCmdDir

    # ── Load checks ──
    checks = loadChecks(args.json, args.json_dir)

    # ── Build device connection ──
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

    else:
        missing = []
        if not args.host:
            missing.append("--host")
        if not args.ssh_user:
            missing.append("--ssh-user")
        if not args.ssh_pass:
            missing.append("--ssh-pass")
        if missing:
            print("ERROR: For --mode ssh you must provide: " + ", ".join(missing), file=sys.stderr)
            sys.exit(1)
        device = SshDevice(args.host, args.port, args.ssh_user, args.ssh_pass)

    # ── Banner ──
    printBanner(device.idString())

    # ── Progress callback ──
    def _progress(idx: int, total: int):
        if args.progress_numbers:
            sys.stdout.write("\r" + f"{idx}/{total}")
            sys.stdout.flush()

    # ── Output paths ──
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    txtDir = os.path.join(args.out, f"txt_report_{timestamp}")
    htmlDir = os.path.join(args.out, f"html_report_{timestamp}")
    os.makedirs(txtDir, exist_ok=True)
    os.makedirs(htmlDir, exist_ok=True)
    txtFile = os.path.join(txtDir, "audit_report.txt")
    htmlFile = os.path.join(htmlDir, "audit_report.html")
    csvFile = os.path.join(htmlDir, "audit_report.csv")

    # ── Root detection ──
    print(f"\n{Colors.BRIGHT_CYAN}🔍 Starting security audit with {len(checks)} checks...{Colors.RESET}\n")

    isRooted, rootMethod = detectRootStatus(device)
    if isRooted:
        print(f"{Colors.GREEN}✓ Root detected ({rootMethod}) — will use su for privileged commands{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}⚠ Device not rooted — some checks may have limited output{Colors.RESET}")
    print()

    # ── Device info ──
    deviceInfo = collectDeviceInfo(device)

    # ── ADB pre-flight ──
    if isinstance(device, AdbDevice):
        preflight = device.shell("echo HARDAX_PREFLIGHT_OK")
        if "HARDAX_PREFLIGHT_OK" not in preflight:
            print(f"{Colors.BRIGHT_RED}✗ ADB pre-flight check failed!{Colors.RESET}")
            print(f"  Response: {preflight}")
            print(f"  {Colors.YELLOW}Attempting reconnect...{Colors.RESET}")
            runLocal(device._base() + ["reconnect"])
            time.sleep(3)
            runLocal(device._base() + ["wait-for-device"], timeout=15)
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

    # ── Run all checks ──
    rows, counts = runChecks(
        device, checks,
        onProgress=_progress,
        showCommands=args.show_commands or not args.progress_numbers,
        isRooted=isRooted,
    )

    if args.progress_numbers:
        print()

    # ── Certificate audit ──
    certs = []
    if args.mode == "adb" and not args.skip_certs:
        certs = auditCertificates(device)

    # ── Generate reports ──
    writeTxtReport(txtFile, deviceInfo, rows, counts, certs, device.idString())
    writeCsvReport(csvFile, rows)
    writeHtmlReport(htmlFile, deviceInfo, rows, counts, certs)

    # ── Close SSH if used ──
    if isinstance(device, SshDevice):
        device.close()

    # ── Summary ──
    print(f"\n{Colors.CYAN}{'═' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BRIGHT_WHITE}✓ HARDAX AUDIT COMPLETED{Colors.RESET}")
    print(f"{Colors.CYAN}{'═' * 70}{Colors.RESET}")
    print(f"{Colors.BRIGHT_WHITE}📱 Target         : {Colors.BOLD}{Colors.BRIGHT_CYAN}{device.idString()}{Colors.RESET}")
    print(f"{Colors.GREEN}✓  Safe Checks   : {Colors.BOLD}{counts['safe']}{Colors.RESET}")
    print(f"{Colors.YELLOW}⚠  Warnings      : {Colors.BOLD}{counts['warning']}{Colors.RESET}")
    print(f"{Colors.BRIGHT_RED}✗  Critical      : {Colors.BOLD}{counts['critical']}{Colors.RESET}")
    print(f"{Colors.BRIGHT_MAGENTA}?  Verify        : {Colors.BOLD}{counts['verify']}{Colors.RESET}")
    print(f"{Colors.CYAN}ℹ  Info          : {Colors.BOLD}{counts['info']}{Colors.RESET}")
    if counts.get("skipped", 0) > 0:
        print(f"{Colors.DIM}⊘  Skipped (ADB) : {Colors.BOLD}{counts['skipped']}{Colors.RESET}")
    print(f"{Colors.CYAN}{'─' * 70}{Colors.RESET}")
    print(f"{Colors.DIM}📄 TXT Report    : {txtFile}{Colors.RESET}")
    print(f"{Colors.DIM}🌐 HTML Report   : {htmlFile}{Colors.RESET}")
    print(f"{Colors.DIM}📊 CSV Report    : {csvFile}{Colors.RESET}")
    print(f"{Colors.CYAN}{'═' * 70}{Colors.RESET}\n")


if __name__ == "__main__":
    main()
