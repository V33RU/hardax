#!/usr/bin/env python3

import argparse
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

__version__ = "1.2.0"

# -------------------------
# Certificate Audit
# -------------------------

def audit_certificates(device: 'Device') -> List[Dict[str, Any]]:
    """
    Pull certificates from device and analyze them.
    Returns list of cert info with expiry/age calculations.
    """
    certs = []
    
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        print(f"{Colors.YELLOW}⚠ cryptography library not installed. Skipping certificate audit.{Colors.RESET}")
        print(f"{Colors.DIM}  Install with: pip install cryptography{Colors.RESET}")
        return []
    
    # Get list of system CA certs
    cert_list_output = device.shell("ls /system/etc/security/cacerts/ 2>/dev/null")
    if not cert_list_output.strip():
        return []
    
    cert_files = [f.strip() for f in cert_list_output.split('\n') if f.strip().endswith('.0')]
    
    print(f"\n{Colors.BRIGHT_CYAN}🔐 Analyzing {len(cert_files)} system certificates...{Colors.RESET}")
    
    today = datetime.now()
    
    for i, cert_file in enumerate(cert_files[:50]):  # Limit to 50 certs for performance
        try:
            # Get cert content directly via shell
            cert_path = f"/system/etc/security/cacerts/{cert_file}"
            cert_pem = device.shell(f"cat {cert_path} 2>/dev/null")
            
            if "-----BEGIN CERTIFICATE-----" not in cert_pem:
                continue
            
            # Parse certificate
            cert_data = cert_pem.encode('utf-8')
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())
            
            # Extract info
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            not_before = cert.not_valid_before_utc.replace(tzinfo=None)
            not_after = cert.not_valid_after_utc.replace(tzinfo=None)
            
            # Calculate age and expiry
            days_old = (today - not_before).days
            days_until_expiry = (not_after - today).days
            
            # Determine status
            if days_until_expiry < 0:
                status = "EXPIRED"
                risk = "critical"
            elif days_until_expiry < 30:
                status = "EXPIRING_SOON"
                risk = "warning"
            elif days_until_expiry < 90:
                status = "CHECK"
                risk = "warning"
            else:
                status = "VALID"
                risk = "safe"
            
            # Extract CN from subject
            cn = "Unknown"
            for part in subject.split(','):
                if part.strip().startswith('CN='):
                    cn = part.strip()[3:]
                    break
            
            certs.append({
                'filename': cert_file,
                'cn': cn[:50] + '...' if len(cn) > 50 else cn,
                'issuer': issuer[:50] + '...' if len(issuer) > 50 else issuer,
                'not_before': not_before.strftime('%Y-%m-%d'),
                'not_after': not_after.strftime('%Y-%m-%d'),
                'days_old': days_old,
                'days_until_expiry': days_until_expiry,
                'status': status,
                'risk': risk,
            })
            
            # Progress indicator
            if (i + 1) % 10 == 0:
                print(f"\r{Colors.DIM}  Processed {i + 1}/{len(cert_files[:50])} certs...{Colors.RESET}", end='', flush=True)
                
        except Exception as e:
            continue
    
    print(f"\r{Colors.GREEN}  ✓ Analyzed {len(certs)} certificates{Colors.RESET}          ")
    
    # Also check for user-installed certs (potential MITM)
    user_certs = device.shell("ls /data/misc/user/0/cacerts-added/ 2>/dev/null")
    if user_certs.strip():
        user_cert_files = [f.strip() for f in user_certs.split('\n') if f.strip()]
        for cert_file in user_cert_files:
            certs.append({
                'filename': cert_file,
                'cn': 'USER INSTALLED CERT',
                'issuer': 'Unknown - User Added',
                'not_before': '-',
                'not_after': '-',
                'days_old': 0,
                'days_until_expiry': 0,
                'status': 'USER_CERT',
                'risk': 'critical',
            })
    
    return sorted(certs, key=lambda x: (x['risk'] != 'critical', x['risk'] != 'warning', x['days_until_expiry']))

# -------------------------
# ANSI Color Codes
# -------------------------

class Colors:
    """ANSI color codes for beautiful terminal output"""
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    
    # Standard colors
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    
    # Bright colors
    BRIGHT_RED = '\033[91m'
    BRIGHT_GREEN = '\033[92m'
    BRIGHT_YELLOW = '\033[93m'
    BRIGHT_BLUE = '\033[94m'
    BRIGHT_MAGENTA = '\033[95m'
    BRIGHT_CYAN = '\033[96m'
    BRIGHT_WHITE = '\033[97m'

# Check if terminal supports colors
def supports_color() -> bool:
    """Check if terminal supports ANSI colors"""
    if not hasattr(sys.stdout, 'isatty'):
        return False
    if not sys.stdout.isatty():
        return False
    if os.environ.get('TERM') == 'dumb':
        return False
    return True

# Disable colors if not supported
if not supports_color():
    for attr in dir(Colors):
        if not attr.startswith('_'):
            setattr(Colors, attr, '')

# -------------------------
# Utilities
# -------------------------

def which(prog: str) -> Optional[str]:
    return shutil.which(prog)

def run_local(cmd: List[str]) -> Tuple[int, str, str]:
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    out, err = proc.communicate()
    return proc.returncode, out, err

def html_escape(s: str) -> str:
    return html.escape(s, quote=False)

def normalize_for_match(s: str) -> str:
    """Normalize line endings but preserve newlines for multi-line pattern matching"""
    return (s or "").replace("\r\n", "\n").replace("\r", "\n")

def bucket_from_level(level: str) -> str:
    lvl = (level or "").strip().lower()
    if lvl in ("critical", "high"):
        return "critical"
    if lvl in ("warning", "medium"):
        return "warning"
    return "info"

# -------------------------
# ADB helpers
# -------------------------

def list_adb_devices() -> list:
    code, out, _ = run_local(["adb", "devices", "-l"])
    if code != 0:
        return []
    lines = [l.strip() for l in out.splitlines()[1:] if l.strip()]
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

def pick_default_serial(user_serial: Optional[str]) -> Optional[str]:
    if user_serial:
        return user_serial
    devs = list_adb_devices()
    healthy = [d for d in devs if d["state"] == "device"]
    if len(healthy) == 1:
        return healthy[0]["serial"]
    return None

def explain_adb_devices_and_exit(exit_code: int = 2):
    devs = list_adb_devices()
    if not devs:
        msg = ("No ADB devices detected.\n\n"
               "Troubleshooting:\n"
               "   Enable Developer options and USB debugging on the device\n"
               "   Trust this computer on the device prompt\n"
               "   Run: adb kill-server && adb start-server\n"
               "   Check USB cable/port or try: adb tcpip 5555; adb connect <ip>:5555\n")
        print(msg, file=sys.stderr)
        sys.exit(exit_code)
    lines = ["Detected ADB endpoints (use --serial <id>):"]
    for d in devs:
        lines.append(f"  - {d['serial']:>24}   {d['state']:<12}   {d['desc']}")
    lines.append("\nNotes:")
    lines.append("   Only devices in state 'device' are usable.")
    lines.append("   If you see 'unauthorized', unlock the phone and accept the RSA fingerprint dialog.")
    lines.append("   If multiple 'device' entries exist, pass --serial <id>.")
    print("\n".join(lines), file=sys.stderr)
    sys.exit(exit_code)

# -------------------------
# Device interfaces
# -------------------------

class Device:
    """Abstract shell runner."""
    def shell(self, command: str) -> str:
        raise NotImplementedError()
    def id_string(self) -> str:
        raise NotImplementedError()

class ADBDevice(Device):
    def __init__(self, serial: Optional[str]):
        self.serial = serial

    def _base(self) -> List[str]:
        return ["adb"] + (["-s", self.serial] if self.serial else [])

    def check_connected(self) -> None:
        code, _, _ = run_local(self._base() + ["get-state"])
        if code != 0:
            _, devs, _ = run_local(["adb", "devices", "-l"])
            raise RuntimeError("No ADB device detected or unauthorized. Output:\n" + devs)

    def shell(self, command: str) -> str:
        code, out, err = run_local(self._base() + ["shell", command])
        txt = (out or "") + (("\n" + err) if err else "")
        return txt.replace("\r", "").strip()

    def id_string(self) -> str:
        return self.serial or "(unknown-serial)"

class SSHDevice(Device):
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
            self.client.connect(hostname=host, port=port, username=user, password=password, look_for_keys=False, allow_agent=False, timeout=20)
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

    def id_string(self) -> str:
        return f"{self.user}@{self.host}:{self.port}"

    def close(self):
        try:
            self.client.close()
        except Exception:
            pass

# -------------------------
# Smart Command Execution with -p Fallback (netstat/ss only)
# -------------------------

def execute_with_p_fallback(device: Device, command: str, show_commands: bool = False, is_rooted: bool = None) -> str:
    """
    Smart execution for netstat/ss commands.
    
    Strategy:
    1. If device is rooted → try with su -c first for full info
    2. If not rooted or su fails → try without su
    3. If -p flag causes issues → remove -p and retry
    
    Returns the best available output.
    """
    
    def is_netstat_or_ss_command(cmd: str) -> bool:
        """Check if command contains netstat or ss"""
        cmd_lower = cmd.lower()
        return 'netstat' in cmd_lower or re.search(r'\bss\b', cmd_lower)
    
    def extract_netstat_ss_command(cmd: str) -> str:
        """Extract the core netstat/ss command from shell wrappers"""
        # Remove sh -c, sh -lc wrappers
        cmd = re.sub(r"sh\s+-[a-z]*c\s+'([^']+)'", r'\1', cmd)
        # Get first command (before ||)
        if '||' in cmd:
            cmd = cmd.split('||')[0].strip()
        # Remove redirections
        cmd = re.sub(r'\s*2>/dev/null', '', cmd)
        return cmd.strip()
    
    def is_output_valid(output: str) -> bool:
        """Check if output has actual data (not just header or error)"""
        if not output or not output.strip():
            return False
        output_lower = output.lower()
        # Check for errors
        if any(err in output_lower for err in ['permission denied', 'not found', 'cannot open', 'invalid']):
            return False
        # Check if it's just a header line
        lines = [l for l in output.strip().split('\n') if l.strip()]
        if len(lines) <= 1:
            # Might just be header "Proto Recv-Q..."
            if lines and ('proto' in lines[0].lower() or 'state' in lines[0].lower()):
                return False
        return True
    
    def has_data_rows(output: str) -> bool:
        """Check if output has actual data rows (not just header)"""
        if not output:
            return False
        lines = [l.strip() for l in output.strip().split('\n') if l.strip()]
        # Filter out header lines
        data_lines = [l for l in lines if not l.lower().startswith('proto') and 
                      not l.lower().startswith('state') and
                      not l.lower().startswith('active')]
        return len(data_lines) > 0
    
    # Check if this is a network command
    if not is_netstat_or_ss_command(command):
        return device.shell(command)
    
    # Extract the core command
    core_cmd = extract_netstat_ss_command(command)
    
    # Determine if we should use netstat or ss
    use_netstat = 'netstat' in core_cmd.lower()
    
    # Build simple commands without wrappers
    if use_netstat:
        # Use -anp for all connections with PID
        simple_cmd = "netstat -anp"
    else:
        simple_cmd = "ss -anp"
    
    results = []
    
    # Strategy 1: If potentially rooted, try with su first
    if is_rooted or is_rooted is None:
        su_cmd = f'su -c "{simple_cmd}"'
        if show_commands:
            print(f"    {Colors.DIM}→ Trying (root): {su_cmd}{Colors.RESET}")
        
        su_result = device.shell(su_cmd)
        
        if su_result and "not found" not in su_result.lower() and is_output_valid(su_result):
            if show_commands:
                print(f"    {Colors.GREEN}→ Got output via su (root){Colors.RESET}")
            # Apply original grep filters if any
            return apply_filters(su_result, command)
    
    # Strategy 2: Try without su
    if show_commands:
        print(f"    {Colors.DIM}→ Trying (non-root): {simple_cmd}{Colors.RESET}")
    
    result = device.shell(simple_cmd)
    
    if result and is_output_valid(result):
        if show_commands:
            print(f"    {Colors.YELLOW}→ Got output (non-root){Colors.RESET}")
        return apply_filters(result, command)
    
    # Strategy 3: Try without -p flag
    simple_cmd_no_p = simple_cmd.replace('-anp', '-an').replace('-lntp', '-lnt').replace('-lnup', '-lnu')
    if simple_cmd_no_p != simple_cmd:
        if show_commands:
            print(f"    {Colors.DIM}→ Trying without -p: {simple_cmd_no_p}{Colors.RESET}")
        
        no_p_result = device.shell(simple_cmd_no_p)
        
        if no_p_result and is_output_valid(no_p_result):
            if show_commands:
                print(f"    {Colors.YELLOW}→ Got output without -p (no PID info){Colors.RESET}")
            return apply_filters(no_p_result, command)
    
    # Strategy 4: Try ss as fallback if netstat failed
    if use_netstat:
        ss_cmd = "ss -anp"
        if is_rooted or is_rooted is None:
            ss_cmd = f'su -c "{ss_cmd}"'
        
        if show_commands:
            print(f"    {Colors.DIM}→ Trying ss fallback: {ss_cmd}{Colors.RESET}")
        
        ss_result = device.shell(ss_cmd)
        
        if ss_result and is_output_valid(ss_result):
            return apply_filters(ss_result, command)
    
    # Return empty with note about failure
    return ""


def apply_filters(output: str, original: str) -> str:
    """
    Emulate a simple shell pipeline for the given base+pipeline string:
      - grep [-i] [-v] [-E] [-F] 'pattern'
      - head -N / tail -N (applied after greps)
    """
    if not output:
        return output

    lines = output.splitlines()

    # Extract pipeline part (everything after first '|')
    pipe = ''
    if '|' in original:
        pipe = original.split('|', 1)[1]
    if not pipe:
        return '\n'.join(lines)

    # Tokenize by '|' boundaries
    stages = [s.strip() for s in pipe.split('|') if s.strip()]

    # Collect greps and optional head/tail
    head_n = None
    tail_n = None
    greps = []
    for st in stages:
        if st.startswith('grep'):
            # flags
            mflags = re.search(r'(^|\s)-([iEvFv]+)', st)
            flags = set(mflags.group(2)) if mflags else set()
            # pattern: '...' or "..." or bare
            pm = re.search(r"""'(.*?)'|"(.*?)"|(\S+)$""", st)
            if not pm:
                continue
            pattern = pm.group(1) or pm.group(2) or pm.group(3)
            greps.append((flags, pattern))
        elif st.startswith('head'):
            m = re.search(r'head\s+-?(\d+)', st)
            if m:
                head_n = int(m.group(1))
        elif st.startswith('tail'):
            m = re.search(r'tail\s+-?(\d+)', st)
            if m:
                tail_n = int(m.group(1))
        else:
            # ignore unknown stages
            pass

    # Apply greps in order
    filtered = lines
    for flags, pattern in greps:
        ignore_case = 'i' in flags
        invert = 'v' in flags
        fixed = 'F' in flags
        extended = 'E' in flags

        if fixed:
            needle = pattern if not ignore_case else pattern.lower()
            def match_fn(s):
                h = s if not ignore_case else s.lower()
                return needle in h
        else:
            pat = pattern if extended else pattern
            try:
                rx = re.compile(pat, re.IGNORECASE if ignore_case else 0)
                def match_fn(s):
                    return bool(rx.search(s))
            except re.error:
                # Fallback to fixed contains
                needle = pattern if not ignore_case else pattern.lower()
                def match_fn(s):
                    h = s if not ignore_case else s.lower()
                    return needle in h

        filtered = [ln for ln in filtered if (not match_fn(ln))] if invert else [ln for ln in filtered if match_fn(ln)]

    # Apply tail/head at the end (like shell)
    if tail_n is not None and tail_n >= 0:
        filtered = filtered[-tail_n:]
    if head_n is not None and head_n >= 0:
        filtered = filtered[:head_n]

    return '\n'.join(filtered)

def detect_root_status(device: Device) -> Tuple[bool, str]:
    """
    Returns (is_rooted, method).
    method ∈ {'adbd-root','magisk','su','su-present-not-working','none'}
    NOTE: This augments the existing logic with an explicit 'su -c id' validation.
    """
    # -----------------------------
    # 1) Try ADBD root (eng/userdebug)
    # -----------------------------
    try:
        if isinstance(device, ADBDevice):
            # Try to elevate adbd itself (only works on eng/userdebug)
            run_local(["adb", "start-server"])
            run_local(device._base() + ["root"])   # ignore message text
            out = device.shell("id 2>/dev/null")
            if out and ("uid=0(" in out or out.strip() == "0"):
                return True, "adbd-root"
    except Exception:
        pass

    # -----------------------------
    # 2) Check for su presence (existence only)
    # -----------------------------
    su_path = device.shell("command -v su 2>/dev/null || which su 2>/dev/null").strip()
    has_su = bool(su_path and "not found" not in su_path.lower())

    # Helper: see if 'timeout' exists; if not, fallback to plain su
    try:
        has_timeout = "yes" in device.shell("command -v timeout >/dev/null 2>&1 && echo yes || echo no").strip().lower()
    except Exception:
        has_timeout = False

    def _su_cmd(cmd: str, seconds: int = 2) -> str:
        if has_timeout:
            return device.shell(f"timeout {seconds} su -c '{cmd}' 2>/dev/null")
        # no timeout available; best-effort attempt (avoid long commands)
        return device.shell(f"su -c '{cmd}' 2>/dev/null")

    # -----------------------------
    # 3) Validate functional su (fast, non-interactive)
    # -----------------------------
    if has_su:
        # Preferred proof: id -u == 0
        out = _su_cmd("id -u", 2).strip()
        if out == "0":
            # Try to classify as Magisk
            ver = _su_cmd("magisk --version", 2).strip() or _su_cmd("magisk -v", 2).strip()
            if ver:
                return True, "magisk"
            # If no version, still rooted with su
            return True, "su"

        # Fallback explicit check you requested:
        # adb shell "timeout 2 su -c id 2>/dev/null"
        id_out = _su_cmd("id", 2)
        if id_out:
            # New: Accept any output that clearly says uid=0(root) → rooted
            if "uid=0(" in id_out or "uid=0" in id_out:
                # If Magisk SELinux context is visible, treat as Magisk
                if "context=u:r:magisk:s0" in id_out:
                    return True, "magisk"
                # Otherwise, try a quick magisk version probe; if none, classify as generic su
                ver = _su_cmd("magisk --version", 2).strip() or _su_cmd("magisk -v", 2).strip()
                return (True, "magisk") if ver else (True, "su")

        # su exists but didn’t grant root (timed out or denied)
        return False, "su-present-not-working"

    # -----------------------------
    # 4) No su + no adbd-root → treat as not rooted
    # -----------------------------
    return False, "none"

# -------------------------
# Banner
# -------------------------

def print_banner(id_line: Optional[str]) -> None:
    """Print beautiful ASCII art banner with colors"""
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
┃  {Colors.YELLOW}[454 Checks]{Colors.RESET} {Colors.GREEN}[17 Categories]{Colors.BRIGHT_CYAN}                                   ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛{Colors.RESET}
""")
    
    if id_line:
        print(f"{Colors.BRIGHT_WHITE}📱 Target Device: {Colors.BOLD}{Colors.BRIGHT_CYAN}{id_line}{Colors.RESET}\n")

# -------------------------
# Device info (Android-friendly)
# -------------------------

def _get_prop_fallback(device: Device, props: List[str]) -> str:
    for p in props:
        v = device.shell(f"getprop {p}").strip()
        if v:
            return f"{v} (from {p})"
    return "(unknown)"

def _get_prop_fallback_with_cpuinfo(device: Device, props: List[str]) -> str:
    for p in props:
        v = device.shell(f"getprop {p}").strip()
        if v:
            return f"{v} (from {p})"
    cpuinfo = device.shell("cat /proc/cpuinfo")
    m = re.search(r"(?i)hardware\s*:\s*(.+)", cpuinfo)
    if m:
        return m.group(1).strip() + " (from /proc/cpuinfo)"
    return "(unknown)"

def collect_device_info(device: Device) -> Dict[str, str]:
    model = _get_prop_fallback(device, ["ro.product.model", "ro.product.device", "ro.product.name"])
    brand = _get_prop_fallback(device, ["ro.product.brand", "ro.product.manufacturer"])
    manufacturer = _get_prop_fallback(device, ["ro.product.manufacturer", "ro.product.brand"])
    name = _get_prop_fallback(device, ["ro.product.name", "ro.product.model"])
    soc_manufacturer = _get_prop_fallback(device, ["ro.soc.manufacturer", "ro.board.platform", "ro.hardware"])
    soc_model = _get_prop_fallback_with_cpuinfo(device, ["ro.soc.model", "ro.hardware", "ro.board.platform"])
    android_version = device.shell("getprop ro.build.version.release").strip()
    sdk_level = device.shell("getprop ro.build.version.sdk").strip()
    build_id = device.shell("getprop ro.build.display.id").strip()
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
        "soc_manufacturer": clean(soc_manufacturer),
        "soc_model": clean(soc_model),
        "android_version": android_version,
        "sdk_level": sdk_level,
        "build_id": build_id,
        "fingerprint": fingerprint,
        "serialno": serialno,
        "timezone": timezone,
    }

# -------------------------
# Checks loading
# -------------------------

REQUIRED_KEYS = {"category", "label", "command", "safe_pattern", "level", "description"}

def _load_checks_from_file(path: str) -> List[Dict[str, Any]]:
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
        if not REQUIRED_KEYS.issubset(c.keys()):
            missing = REQUIRED_KEYS - set(c.keys())
            raise ValueError(f"{os.path.basename(path)}: check #{i} missing keys: {', '.join(sorted(missing))}")
        valid.append(c)
    return valid

def load_checks(json_path: Optional[str], json_dir: Optional[str]) -> List[Dict[str, Any]]:
    merged: List[Dict[str, Any]] = []

    if json_path:
        if not os.path.isfile(json_path):
            print(f"ERROR: JSON file not found: {json_path}", file=sys.stderr)
            sys.exit(1)
        try:
            merged.extend(_load_checks_from_file(json_path))
        except Exception as e:
            print(f"ERROR parsing {json_path}: {e}", file=sys.stderr)
            sys.exit(1)

    if json_dir:
        if not os.path.isdir(json_dir):
            print(f"ERROR: JSON directory not found: {json_dir}", file=sys.stderr)
            sys.exit(1)
        for fname in sorted(os.listdir(json_dir)):
            if not fname.lower().endswith(".json"):
                continue
            fpath = os.path.join(json_dir, fname)
            try:
                merged.extend(_load_checks_from_file(fpath))
            except Exception as e:
                print(f"ERROR parsing {fpath}: {e}", file=sys.stderr)
                sys.exit(1)

    if not merged:
        print("ERROR: No checks loaded. Provide --json or --json-dir.", file=sys.stderr)
        sys.exit(1)

    return merged

# -------------------------
# Pattern validation
# -------------------------

def validate_check_pattern(check: Dict[str, Any]) -> List[str]:
    """Validate pattern for common issues"""
    issues = []
    pattern = check.get("safe_pattern", "")
    label = check.get("label", "unknown")
    
    if not pattern:
        return issues
    
    # Check for common regex issues
    try:
        re.compile(pattern, re.IGNORECASE | re.MULTILINE | re.DOTALL)
    except re.error as e:
        issues.append(f"[{label}] Invalid regex: {e}")
    
    return issues

# -------------------------
# Reporting
# -------------------------

def write_csv(csv_path: str, rows: List[Dict[str, Any]]) -> None:
    fieldnames = ["timestamp", "category", "label", "level", "bucket", "status",
                  "matched", "command", "result", "description"]
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fieldnames})

def write_html(html_path: str, device: Dict[str, str], rows: List[Dict[str, Any]], counts: Dict[str, int], certs: List[Dict[str, Any]] = None) -> None:
    """Write modern HTML report with collapsible category sections and certificate table"""
    
    # --- Certificate table (always render; show empty-state when none) ---
    cert_table_html = ""
    cert_rows_html = ""
    expired_count = expiring_count = user_count = valid_count = 0

    if certs:
        cert_rows = []
        for c in certs:
            risk_class = c['risk']
            status_emoji = {
                'EXPIRED': '\U0001F534',
                'EXPIRING_SOON': '\U0001F7E1',
                'CHECK': '\U0001F7E1',
                'USER_CERT': '⚠️',
                'VALID': '\U0001F7E2'
            }.get(c['status'], '⚪')
            days_info = f"{c['days_old']:,}" if isinstance(c['days_old'], int) else '-'
            expiry_info = f"{c['days_until_expiry']:,}" if isinstance(c['days_until_expiry'], int) else '-'
            cert_rows.append(
                f"<tr class=\"cert-row {risk_class}\">\n"
                f"<td>{html_escape(c['cn'])}</td>\n"
                f"<td>{html_escape(c['not_before'])}</td>\n"
                f"<td>{html_escape(c['not_after'])}</td>\n"
                f"<td class=\"days-old\">{days_info}</td>\n"
                f"<td class=\"days-expiry\">{expiry_info}</td>\n"
                f"<td><span class=\"cert-status {risk_class}\">{status_emoji} {c['status']}</span></td>\n"
                f"</tr>"
            )
        cert_rows_html = "\n".join(cert_rows)
        expired_count = sum(1 for c in certs if c['status'] == 'EXPIRED')
        expiring_count = sum(1 for c in certs if c['status'] in ('EXPIRING_SOON', 'CHECK'))
        user_count = sum(1 for c in certs if c['status'] == 'USER_CERT')
        valid_count = sum(1 for c in certs if c['status'] == 'VALID')

    cert_table_html = (
        f"<div class=\"cert-section category-section\" id=\"cert_section\">\n"
        f"  <div class=\"category-header\" onclick=\"toggleCategory('cert_section')\">\n"
        f"    <div class=\"category-title\">\n"
        f"      <span class=\"toggle-icon\">▶</span>\n"
        f"      <span class=\"category-name\">\U0001F510 CERTIFICATE AUDIT</span>\n"
        f"      <span class=\"check-count\">({len(certs) if certs else 0} certificates)</span>\n"
        f"    </div>\n"
        f"    <div class=\"category-stats\">\n"
        f"      <span class=\"cat-badge critical\">{expired_count} Expired</span>\n"
        f"      <span class=\"cat-badge warning\">{expiring_count} Expiring</span>\n"
        f"      <span class=\"cat-badge critical\">{user_count} User Installed</span>\n"
        f"      <span class=\"cat-badge safe\">{valid_count} Valid</span>\n"
        f"    </div>\n"
        f"  </div>\n"
        f"  <div class=\"category-content\">\n"
        f"    <div class=\"cert-table-container\">\n"
        f"      <table class=\"cert-table\">\n"
        f"        <thead>\n"
        f"          <tr>\n"
        f"            <th>Common Name (CN)</th>\n"
        f"            <th>Valid From</th>\n"
        f"            <th>Valid Until</th>\n"
        f"            <th>Days Old</th>\n"
        f"            <th>Days to Expiry</th>\n"
        f"            <th>Status</th>\n"
        f"          </tr>\n"
        f"        </thead>\n"
        f"        <tbody>\n"
        f"          {cert_rows_html if certs else '<tr><td colspan=\"6\" style=\"color:#a3a3a3;\">No certificates parsed. (Tip: ensure cryptography is installed/updated and the device exposes APEX Conscrypt CA store.)</td></tr>'}\n"
        f"        </tbody>\n"
        f"      </table>\n"
        f"    </div>\n"
        f"  </div>\n"
        f"</div>"
        )
    # Group rows by category
    categories = {}
    for r in rows:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = {"rows": [], "stats": {"CRITICAL": 0, "WARNING": 0, "VERIFY": 0, "SAFE": 0, "INFO": 0}}
        categories[cat]["rows"].append(r)
        status = r["status"]
        if status in categories[cat]["stats"]:
            categories[cat]["stats"][status] += 1
        else:
            categories[cat]["stats"]["INFO"] += 1
    
    # Build category sections HTML
    category_sections = []
    for cat_idx, (cat_name, cat_data) in enumerate(sorted(categories.items())):
        stats = cat_data["stats"]
        cat_rows = cat_data["rows"]
        
        # Build stats badges
        badges = []
        if stats["CRITICAL"] > 0:
            badges.append(f'<span class="cat-badge critical">{stats["CRITICAL"]} Critical</span>')
        if stats["WARNING"] > 0:
            badges.append(f'<span class="cat-badge warning">{stats["WARNING"]} Warning</span>')
        if stats["VERIFY"] > 0:
            badges.append(f'<span class="cat-badge verify">{stats["VERIFY"]} Verify</span>')
        if stats["SAFE"] > 0:
            badges.append(f'<span class="cat-badge safe">{stats["SAFE"]} Safe</span>')
        if stats["INFO"] > 0:
            badges.append(f'<span class="cat-badge info">{stats["INFO"]} Info</span>')
        badges_html = " ".join(badges)
        
        # Build check items
        items_html = []
        for r in cat_rows:
            cmd_esc = html_escape(r["command"])
            res_esc = html_escape(r["result"])
            desc_esc = html_escape(r["description"])
            label_esc = html_escape(r["label"])
            status = r["status"]
            css_class = {"SAFE": "safe", "WARNING": "warning", "CRITICAL": "critical", "VERIFY": "verify"}.get(status, "info")
            
            items_html.append(f'''
        <div class="check-item {css_class}" data-search="{html_escape(r['label'].lower())} {html_escape(r['description'].lower())}">
          <div class="check-header">
            <span class="check-label">{label_esc}</span>
            <span class="status-badge {css_class}">{status}</span>
          </div>
          <p class="check-desc">{desc_esc}</p>
          <div class="check-details">
            <div class="detail-block">
              <span class="detail-label">Command:</span>
              <pre><code>{cmd_esc}</code></pre>
            </div>
            <div class="detail-block">
              <span class="detail-label">Result:</span>
              <pre><code>{res_esc if res_esc else "(empty)"}</code></pre>
            </div>
          </div>
        </div>''')
        
        items_joined = "\n".join(items_html)
        
        category_sections.append(f'''
    <div class="category-section" id="cat_{cat_idx}">
      <div class="category-header" onclick="toggleCategory('cat_{cat_idx}')">
        <div class="category-title">
          <span class="toggle-icon">▶</span>
          <span class="category-name">{html_escape(cat_name)}</span>
          <span class="check-count">({len(cat_rows)} checks)</span>
        </div>
        <div class="category-stats">
          {badges_html}
        </div>
      </div>
      <div class="category-content">
        {items_joined}
      </div>
    </div>''')
    
    categories_html = "\n".join(category_sections)
    
    # Device info items
    device_items = []
    for key, label in [("model", "Model"), ("brand", "Brand"), ("manufacturer", "Manufacturer"),
                       ("android_version", "Android"), ("sdk_level", "SDK"), ("build_id", "Build"),
                       ("serialno", "Serial"), ("soc_model", "SoC")]:
        val = device.get(key, "")
        if val and val != "(unknown)":
            device_items.append(f'<div class="device-item"><span class="device-label">{label}</span><span class="device-value">{html_escape(val)}</span></div>')
    device_html = "\n".join(device_items)
    
    total_checks = len(rows)
    
    doc = f'''<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>HARDAX - Security Audit Report</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    :root {{
      --bg-primary: #0a0a0a;
      --bg-secondary: #141414;
      --bg-tertiary: #1f1f1f;
      --text-primary: #e5e5e5;
      --text-secondary: #a3a3a3;
      --border-color: #2a2a2a;
      --accent: #3b82f6;
      --critical: #ef4444;
      --warning: #f59e0b;
      --safe: #22c55e;
      --info: #3b82f6;
      --verify: #a855f7;
    }}
    
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    
    body {{
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
    }}
    
    .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
    
    /* Toolbar */
    .toolbar {{
      position: sticky;
      top: 0;
      z-index: 1000;
      background: linear-gradient(135deg, #1e3a5f 0%, #0f172a 100%);
      padding: 16px 24px;
      border-radius: 12px;
      margin-bottom: 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.15);
    }}
    
    .toolbar-brand {{
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    
    .toolbar-brand h1 {{
      color: #fff;
      font-size: 1.5rem;
      font-weight: 700;
      letter-spacing: -0.5px;
    }}
    
    .toolbar-brand .version {{
      background: rgba(255,255,255,0.15);
      color: #94a3b8;
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 0.75rem;
    }}
    
    .toolbar-controls {{
      display: flex;
      align-items: center;
      gap: 10px;
    }}
    
    .search-box {{
      background: rgba(255,255,255,0.1);
      border: 1px solid rgba(255,255,255,0.2);
      border-radius: 8px;
      padding: 10px 16px;
      color: #fff;
      font-size: 0.9rem;
      width: 280px;
      outline: none;
      transition: all 0.2s;
    }}
    
    .search-box::placeholder {{ color: rgba(255,255,255,0.5); }}
    .search-box:focus {{ background: rgba(255,255,255,0.15); border-color: var(--accent); }}
    
    .btn {{
      background: rgba(255,255,255,0.1);
      border: 1px solid rgba(255,255,255,0.2);
      color: #fff;
      padding: 10px 16px;
      border-radius: 8px;
      cursor: pointer;
      font-size: 0.85rem;
      font-weight: 500;
      transition: all 0.2s;
    }}
    
    .btn:hover {{ background: rgba(255,255,255,0.2); }}
    
    /* Summary Cards */
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }}
    
    .summary-card {{
      background: var(--bg-secondary);
      border-radius: 12px;
      padding: 20px;
      border: 1px solid var(--border-color);
      text-align: center;
      transition: transform 0.2s, box-shadow 0.2s;
    }}
    
    .summary-card:hover {{ transform: translateY(-2px); box-shadow: 0 8px 25px rgba(0,0,0,0.1); }}
    
    .summary-card.critical {{ border-left: 4px solid var(--critical); }}
    .summary-card.warning {{ border-left: 4px solid var(--warning); }}
    .summary-card.verify {{ border-left: 4px solid var(--verify); }}
    .summary-card.safe {{ border-left: 4px solid var(--safe); }}
    .summary-card.info {{ border-left: 4px solid var(--info); }}
    .summary-card.total {{ border-left: 4px solid var(--accent); }}
    
    .summary-card .number {{
      font-size: 2.5rem;
      font-weight: 700;
      line-height: 1;
      margin-bottom: 8px;
    }}
    
    .summary-card.critical .number {{ color: var(--critical); }}
    .summary-card.warning .number {{ color: var(--warning); }}
    .summary-card.verify .number {{ color: var(--verify); }}
    .summary-card.safe .number {{ color: var(--safe); }}
    .summary-card.info .number {{ color: var(--info); }}
    .summary-card.total .number {{ color: var(--accent); }}
    
    .summary-card .label {{
      color: var(--text-secondary);
      font-size: 0.9rem;
      font-weight: 500;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    
    /* Device Info & Chart Row */
    .info-row {{
      display: grid;
      grid-template-columns: 1fr 300px;
      gap: 24px;
      margin-bottom: 24px;
    }}
    
    @media (max-width: 900px) {{
      .info-row {{ grid-template-columns: 1fr; }}
    }}
    
    .device-card {{
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      border-radius: 12px;
      padding: 24px;
      color: #fff;
    }}
    
    .device-card h2 {{
      font-size: 1.1rem;
      margin-bottom: 16px;
      opacity: 0.9;
    }}
    
    .device-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 12px;
    }}
    
    .device-item {{
      background: rgba(255,255,255,0.15);
      padding: 12px;
      border-radius: 8px;
    }}
    
    .device-label {{
      display: block;
      font-size: 0.75rem;
      opacity: 0.8;
      margin-bottom: 4px;
    }}
    
    .device-value {{
      font-weight: 600;
      font-size: 0.9rem;
    }}
    
    .chart-card {{
      background: var(--bg-secondary);
      border-radius: 12px;
      padding: 20px;
      border: 1px solid var(--border-color);
      display: flex;
      align-items: center;
      justify-content: center;
    }}
    
    /* Category Sections */
    .category-section {{
      background: var(--bg-secondary);
      border-radius: 12px;
      margin-bottom: 16px;
      border: 1px solid var(--border-color);
      overflow: hidden;
    }}
    
    .category-header {{
      background: var(--bg-tertiary);
      padding: 16px 20px;
      cursor: pointer;
      display: flex;
      justify-content: space-between;
      align-items: center;
      transition: background 0.2s;
      user-select: none;
    }}
    
    .category-header:hover {{ background: var(--border-color); }}
    
    .category-title {{
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    
    .toggle-icon {{
      font-size: 0.8rem;
      color: var(--text-secondary);
      transition: transform 0.3s;
    }}
    
    .category-section.expanded .toggle-icon {{ transform: rotate(90deg); }}
    
    .category-name {{
      font-weight: 600;
      font-size: 1rem;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    
    .check-count {{
      color: var(--text-secondary);
      font-size: 0.85rem;
      font-weight: normal;
    }}
    
    .category-stats {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }}
    
    .cat-badge {{
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 0.75rem;
      font-weight: 600;
    }}
    
    .cat-badge.critical {{ background: rgba(239,68,68,0.15); color: var(--critical); }}
    .cat-badge.warning {{ background: rgba(245,158,11,0.15); color: var(--warning); }}
    .cat-badge.verify {{ background: rgba(168,85,247,0.15); color: var(--verify); }}
    .cat-badge.safe {{ background: rgba(34,197,94,0.15); color: var(--safe); }}
    .cat-badge.info {{ background: rgba(59,130,246,0.15); color: var(--info); }}
    
    .category-content {{
      display: none;
      padding: 16px 20px;
    }}
    
    .category-section.expanded .category-content {{ display: block; }}
    
    /* Check Items */
    .check-item {{
      background: var(--bg-tertiary);
      border-radius: 8px;
      padding: 16px;
      margin-bottom: 12px;
      border-left: 4px solid var(--border-color);
    }}
    
    .check-item.critical {{ border-left-color: var(--critical); }}
    .check-item.warning {{ border-left-color: var(--warning); }}
    .check-item.verify {{ border-left-color: var(--verify); }}
    .check-item.safe {{ border-left-color: var(--safe); }}
    .check-item.info {{ border-left-color: var(--info); }}
    
    .check-item:last-child {{ margin-bottom: 0; }}
    
    .check-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 8px;
    }}
    
    .check-label {{
      font-weight: 600;
      font-size: 0.95rem;
    }}
    
    .status-badge {{
      padding: 4px 12px;
      border-radius: 20px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
    }}
    
    .status-badge.critical {{ background: var(--critical); color: #fff; }}
    .status-badge.warning {{ background: var(--warning); color: #fff; }}
    .status-badge.verify {{ background: var(--verify); color: #fff; }}
    .status-badge.safe {{ background: var(--safe); color: #fff; }}
    .status-badge.info {{ background: var(--info); color: #fff; }}
    
    .check-desc {{
      color: var(--text-secondary);
      font-size: 0.85rem;
      margin-bottom: 12px;
    }}
    
    .detail-block {{
      margin-bottom: 10px;
    }}
    
    .detail-label {{
      display: block;
      font-size: 0.75rem;
      color: var(--text-secondary);
      margin-bottom: 4px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }}
    
    pre {{
      background: #1e293b;
      color: #a5d6a7;
      padding: 12px;
      border-radius: 6px;
      overflow-x: auto;
      font-size: 0.8rem;
      max-height: 200px;
      white-space: pre-wrap;
      word-break: break-word;
    }}
    
    /* Footer */
    footer {{
      text-align: center;
      padding: 24px;
      color: var(--text-secondary);
      font-size: 0.85rem;
      border-top: 1px solid var(--border-color);
      margin-top: 40px;
    }}
    
    .hidden {{ display: none !important; }}
    
    /* Certificate Table Styles */
    .cert-section {{
      background: var(--bg-secondary);
      border-radius: 12px;
      margin-bottom: 24px;
      border: 1px solid var(--border-color);
      overflow: hidden;
    }}
    
    .cert-section .category-content {{
      padding: 16px 20px;
    }}
    
    .cert-table-container {{
      overflow-x: auto;
      border-radius: 8px;
      border: 1px solid var(--border-color);
    }}
    
    .cert-table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.85rem;
    }}
    
    .cert-table th {{
      background: var(--bg-tertiary);
      padding: 12px 16px;
      text-align: left;
      font-weight: 600;
      text-transform: uppercase;
      font-size: 0.75rem;
      letter-spacing: 0.5px;
      color: var(--text-secondary);
      border-bottom: 2px solid var(--border-color);
    }}
    
    .cert-table td {{
      padding: 10px 16px;
      border-bottom: 1px solid var(--border-color);
    }}
    
    .cert-row:hover {{
      background: var(--bg-tertiary);
    }}
    
    .cert-row.critical {{
      background: rgba(239,68,68,0.08);
    }}
    
    .cert-row.warning {{
      background: rgba(245,158,11,0.08);
    }}
    
    .days-old, .days-expiry {{
      font-family: monospace;
      text-align: right;
    }}
    
    .cert-status {{
      padding: 4px 10px;
      border-radius: 12px;
      font-size: 0.75rem;
      font-weight: 600;
      white-space: nowrap;
    }}
    
    .cert-status.critical {{ background: rgba(239,68,68,0.2); color: var(--critical); }}
    .cert-status.warning {{ background: rgba(245,158,11,0.2); color: var(--warning); }}
    .cert-status.safe {{ background: rgba(34,197,94,0.2); color: var(--safe); }}
  </style>
</head>
<body>
  <div class="container">
    <div class="toolbar">
      <div class="toolbar-brand">
        <h1>🛡️ HARDAX</h1>
        <span class="version">v{__version__}</span>
      </div>
      <div class="toolbar-controls">
        <input type="text" class="search-box" id="searchInput" placeholder="🔍 Search checks...">
        <button class="btn" onclick="expandAll()">Expand All</button>
        <button class="btn" onclick="collapseAll()">Collapse All</button>
      </div>
    </div>
    
    <div class="summary-grid">
      <div class="summary-card critical">
        <div class="number">{counts.get("critical", 0)}</div>
        <div class="label">Critical</div>
      </div>
      <div class="summary-card warning">
        <div class="number">{counts.get("warning", 0)}</div>
        <div class="label">Warnings</div>
      </div>
      <div class="summary-card verify">
        <div class="number">{counts.get("verify", 0)}</div>
        <div class="label">Verify</div>
      </div>
      <div class="summary-card safe">
        <div class="number">{counts.get("safe", 0)}</div>
        <div class="label">Safe</div>
      </div>
      <div class="summary-card info">
        <div class="number">{counts.get("info", 0)}</div>
        <div class="label">Info</div>
      </div>
      <div class="summary-card total">
        <div class="number">{total_checks}</div>
        <div class="label">Total Checks</div>
      </div>
    </div>
    
    <div class="info-row">
      <div class="device-card">
        <h2>📱 Device Information</h2>
        <div class="device-grid">
          {device_html}
        </div>
      </div>
      <div class="chart-card">
        <canvas id="summaryChart" width="250" height="250"></canvas>
      </div>
    </div>
    
    {cert_table_html}
    
    <div id="categoriesContainer">
      {categories_html}
    </div>
    
    <footer>
      <p><strong>HARDAX</strong> - Hardening Audit eXaminer | Report generated: {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
      <p>Android OS based IoT Devices Security Configuration Auditor</p>
    </footer>
  </div>
  
  <script>
    // Category toggle
    function toggleCategory(catId) {{
      const section = document.getElementById(catId);
      section.classList.toggle('expanded');
    }}
    
    // Expand/Collapse all
    function expandAll() {{
      document.querySelectorAll('.category-section').forEach(s => s.classList.add('expanded'));
    }}
    
    function collapseAll() {{
      document.querySelectorAll('.category-section').forEach(s => s.classList.remove('expanded'));
    }}
    
    // Search functionality
    document.getElementById('searchInput').addEventListener('input', function(e) {{
      const query = e.target.value.toLowerCase().trim();
      
      document.querySelectorAll('.category-section').forEach(section => {{
        const items = section.querySelectorAll('.check-item');
        let visibleCount = 0;
        
        items.forEach(item => {{
          const searchText = item.getAttribute('data-search') || '';
          const matches = !query || searchText.includes(query);
          item.classList.toggle('hidden', !matches);
          if (matches) visibleCount++;
        }});
        
        section.classList.toggle('hidden', visibleCount === 0);
        if (query && visibleCount > 0) {{
          section.classList.add('expanded');
        }}
      }});
    }});
    
    // Chart
    window.addEventListener('load', function() {{
      const ctx = document.getElementById('summaryChart').getContext('2d');
      new Chart(ctx, {{
        type: 'doughnut',
        data: {{
          labels: ['Critical', 'Warning', 'Verify', 'Safe', 'Info'],
          datasets: [{{
            data: [{counts.get("critical", 0)}, {counts.get("warning", 0)}, {counts.get("verify", 0)}, {counts.get("safe", 0)}, {counts.get("info", 0)}],
            backgroundColor: ['#ef4444', '#f59e0b', '#a855f7', '#22c55e', '#3b82f6'],
            borderWidth: 0
          }}]
        }},
        options: {{
          responsive: true,
          cutout: '65%',
          plugins: {{
            legend: {{
              position: 'bottom',
              labels: {{
                padding: 15,
                usePointStyle: true,
                font: {{ size: 11 }}
              }}
            }}
          }}
        }}
      }});
    }});
  </script>
</body>
</html>'''
    
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(doc)

# -------------------------
# Check execution
# -------------------------

def is_null_response(output: str) -> bool:
    """Check if output is specifically 'null' - needs manual verification"""
    if not output:
        return False
    output_lower = output.lower().strip()
    return output_lower in ['null', 'none', '(null)', '(none)']

def is_empty_or_error(output: str) -> bool:
    """Check if output is empty or indicates an error/unsupported command"""
    if not output:
        return True
    output_lower = output.lower().strip()
    # Common indicators of no data / unsupported command
    error_indicators = [
        'not found', 'no such', 'error', 'exception',
        'permission denied', 'unknown', 'invalid', 'failed',
        'inaccessible', 'cmd: can\'t find', 'not supported',
        'service not found', 'does not exist', 'no output'
    ]
    if output_lower in ['', '(empty)']:
        return True
    for indicator in error_indicators:
        if indicator in output_lower and len(output_lower) < 100:
            return True
    return False

def run_checks(device: Device, checks: List[Dict[str, Any]], on_progress=None, show_commands: bool = False, is_rooted: bool = False) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    rows: List[Dict[str, Any]] = []
    counts = {"safe": 0, "warning": 0, "critical": 0, "info": 0, "verify": 0}
    total = len(checks)
    start_time = time.time()

    for idx, chk in enumerate(checks, start=1):
        category = chk.get("category", "General")
        label = chk.get("label", "Unnamed")
        command = chk.get("command", "")
        safe_pattern = chk.get("safe_pattern", "")
        level = chk.get("level", "info")
        desc = chk.get("description", "")
        # New: allow checks to specify if empty means safe
        empty_is_safe = chk.get("empty_is_safe", False)
        # New: allow checks to require output (empty = verify)
        requires_output = chk.get("requires_output", True)
        # New: allow checks to specify if null means safe
        null_is_safe = chk.get("null_is_safe", False)

        raw = execute_with_p_fallback(device, command, show_commands, is_rooted=is_rooted) if command else ""
        normalized = normalize_for_match(raw)
        bucket = bucket_from_level(level)

        matched = False
        needs_verification = False
        
        # Check if output is empty, error, or null
        output_empty = is_empty_or_error(raw)
        output_is_null = is_null_response(raw)
        
        if safe_pattern:
            try:
                matched = bool(re.search(safe_pattern, normalized, re.IGNORECASE | re.MULTILINE | re.DOTALL))
            except re.error:
                matched = safe_pattern.lower() in normalized.lower()

        # Determine status with improved logic
        if output_is_null:
            # NULL output - check if null is explicitly allowed in safe_pattern
            null_in_pattern = safe_pattern and 'null' in safe_pattern.lower()
            if null_is_safe or null_in_pattern:
                status = "SAFE"
                counts["safe"] += 1
            else:
                # NULL without explicit allowance = needs manual verification
                status = "VERIFY"
                counts["verify"] += 1
                needs_verification = True
        elif matched:
            status = "SAFE"
            counts["safe"] += 1
        elif output_empty:
            # Empty output handling
            if empty_is_safe:
                # Some checks consider empty as safe (e.g., "no bad apps found")
                status = "SAFE"
                counts["safe"] += 1
            elif requires_output and bucket in ("critical", "warning"):
                # Empty output for critical/warning checks = needs manual verification
                status = "VERIFY"
                counts["verify"] += 1
                needs_verification = True
            else:
                # For info-level checks, empty is just info
                status = "INFO"
                counts["info"] += 1
        else:
            # We have actual output that doesn't match safe pattern
            if bucket == "critical":
                status = "CRITICAL"
                counts["critical"] += 1
            elif bucket == "warning":
                status = "WARNING"
                counts["warning"] += 1
            else:
                status = "INFO"
                counts["info"] += 1

        # Progress display
        if on_progress or show_commands:
            try:
                elapsed = time.time() - start_time
                avg_time = elapsed / idx if idx > 0 else 0
                remaining = int(avg_time * (total - idx))
                eta_str = f"{remaining // 60}m {remaining % 60}s" if remaining > 60 else f"{remaining}s"
                percentage = (idx / total) * 100
                
                # Status colors
                if status == "SAFE":
                    status_color = Colors.GREEN
                    status_symbol = "✓"
                elif status == "CRITICAL":
                    status_color = Colors.BRIGHT_RED
                    status_symbol = "✗"
                elif status == "WARNING":
                    status_color = Colors.YELLOW
                    status_symbol = "⚠"
                elif status == "VERIFY":
                    status_color = Colors.BRIGHT_MAGENTA
                    status_symbol = "?"
                else:
                    status_color = Colors.CYAN
                    status_symbol = "ℹ"
                
                # Progress bar
                bar_width = 30
                filled = int((idx / total) * bar_width)
                bar = '█' * filled + '░' * (bar_width - filled)
                
                print(f"\r{Colors.CYAN}[{idx:3d}/{total:3d}]{Colors.RESET} "
                      f"{Colors.BRIGHT_BLUE}[{bar}]{Colors.RESET} "
                      f"{Colors.BRIGHT_WHITE}{percentage:5.1f}%{Colors.RESET} "
                      f"{Colors.DIM}ETA: {eta_str}{Colors.RESET}", end='', flush=True)
                
                if show_commands:
                    print()
                    label_display = label[:50] + "..." if len(label) > 50 else label
                    print(f"  {Colors.BRIGHT_CYAN}▶{Colors.RESET} {Colors.BOLD}{label_display}{Colors.RESET} "
                          f"{status_color}[{status_symbol} {status}]{Colors.RESET}")
                    cmd_display = command[:70] + "..." if len(command) > 70 else command
                    print(f"    {Colors.DIM}$ {cmd_display}{Colors.RESET}", flush=True)
                
                if on_progress:
                    on_progress(idx, total)
            except Exception:
                pass

        # For VERIFY status, add note to description
        display_desc = desc
        display_result = raw
        if needs_verification:
            if output_is_null:
                display_desc = desc + " [⚠ Manual verification required - value is NULL]"
                display_result = "null (Setting may not exist or is not configured)"
            else:
                display_desc = desc + " [⚠ Manual verification required - empty/unsupported output]"
                if not raw.strip():
                    display_result = "(No output - command may not be supported on this device)"
        
        rows.append({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "category": category,
            "label": label,
            "level": level,
            "bucket": bucket,
            "status": status,
            "matched": str(matched),
            "command": command,
            "result": display_result,
            "description": display_desc,
            "needs_verification": needs_verification,
        })
    
    print()
    return rows, counts

# -------------------------
# Main
# -------------------------

def main():
    ap = argparse.ArgumentParser(
        description="HARDAX - Hardening Audit eXaminer for Android/IoT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --json-dir ./commands
  %(prog)s --json-dir ./commands --serial DEVICE123
  %(prog)s --mode ssh --host 192.168.1.100 --ssh-user root --ssh-pass password
        """
    )
    ap.add_argument("--version", action="version", version=f"HARDAX v{__version__}")
    ap.add_argument("--mode", choices=["adb", "ssh"], default="adb", help="How to run commands (default: adb)")
    # ADB
    ap.add_argument("--json", help="Path to single commands JSON")
    ap.add_argument("--json-dir", help="Folder with *.json files to merge")
    ap.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL", ""), help="ADB serial")
    # SSH
    ap.add_argument("--host", help="SSH host")
    ap.add_argument("--port", type=int, default=22, help="SSH port")
    ap.add_argument("--ssh-user", help="SSH username")
    ap.add_argument("--ssh-pass", help="SSH password")
    # Output
    ap.add_argument("--out", default="hardax_output", help="Output directory")
    ap.add_argument("--progress-numbers", action="store_true", help="Show progress counter")
    ap.add_argument("--show-commands", action="store_true", help="Display each command")
    ap.add_argument("--skip-certs", action="store_true", help="Skip certificate audit")

    args = ap.parse_args()

    # Auto-detect json-dir if not specified
    if not args.json and not args.json_dir:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        default_cmd_dir = os.path.join(script_dir, "commands")
        if os.path.isdir(default_cmd_dir):
            args.json_dir = default_cmd_dir

    # Load checks
    checks = load_checks(args.json, args.json_dir)

    # Device selection
    device: Device
    if args.mode == "adb":
        if which("adb") is None:
            print("ERROR: 'adb' not found in PATH.", file=sys.stderr)
            sys.exit(1)
        run_local(["adb", "start-server"])

        serial = (args.serial or "").strip() or None
        serial = pick_default_serial(serial)
        if not serial:
            explain_adb_devices_and_exit(exit_code=2)

        adb_dev = ADBDevice(serial)
        try:
            adb_dev.check_connected()
        except RuntimeError as e:
            print(str(e), file=sys.stderr)
            explain_adb_devices_and_exit(exit_code=3)
        device = adb_dev

    else:  # SSH mode
        missing = []
        if not args.host: missing.append("--host")
        if not args.ssh_user: missing.append("--ssh-user")
        if not args.ssh_pass: missing.append("--ssh-pass")
        if missing:
            print("ERROR: For --mode ssh you must provide: " + ", ".join(missing), file=sys.stderr)
            sys.exit(1)
        device = SSHDevice(args.host, args.port, args.ssh_user, args.ssh_pass)

    # Banner
    print_banner(device.id_string())

    # Progress callback
    def _progress(idx: int, total: int):
        if args.progress_numbers:
            sys.stdout.write("\r" + f"{idx}/{total}")
            sys.stdout.flush()

    # Output paths
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    txt_dir = os.path.join(args.out, f"txt_report_{timestamp}")
    html_dir = os.path.join(args.out, f"html_report_{timestamp}")
    os.makedirs(txt_dir, exist_ok=True)
    os.makedirs(html_dir, exist_ok=True)
    txt_file = os.path.join(txt_dir, "audit_report.txt")
    html_file = os.path.join(html_dir, "audit_report.html")
    csv_file = os.path.join(html_dir, "audit_report.csv")

    # Run audit
    print(f"\n{Colors.BRIGHT_CYAN}🔍 Starting security audit with {len(checks)} checks...{Colors.RESET}\n")
    
    # Detect root status first
    is_rooted, root_method = detect_root_status(device)
    if is_rooted:
        print(f"{Colors.GREEN}✓ Root detected ({root_method}) - will use su for privileged commands{Colors.RESET}")
    else:
        print(f"{Colors.YELLOW}⚠ Device not rooted - some checks may have limited output{Colors.RESET}")
    print()
    
    device_info = collect_device_info(device)
    rows, counts = run_checks(device, checks, on_progress=_progress, show_commands=args.show_commands or not args.progress_numbers, is_rooted=is_rooted)

    if args.progress_numbers:
        print()

    # Certificate Audit
    certs = []
    if args.mode == "adb" and not args.skip_certs:
        certs = audit_certificates(device)

    # TXT Report
    with open(txt_file, "w", encoding="utf-8") as f:
        f.write(f"HARDAX - Hardening Audit eXaminer Report\nGenerated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("Device Information\n" + "=" * 40 + "\n")
        for k in ["model", "brand", "manufacturer", "name", "soc_manufacturer", "soc_model",
                  "android_version", "sdk_level", "build_id", "fingerprint", "serialno", "timezone"]:
            f.write(f"{k.replace('_', ' ').title()}: {device_info.get(k, '')}\n")
        
        # Certificate section in TXT
        if certs:
            f.write("\n" + "=" * 40 + "\nCertificate Audit\n" + "=" * 40 + "\n")
            f.write(f"{'CN':<40} {'Valid From':<12} {'Valid Until':<12} {'Days Old':>10} {'Expiry':>10} {'Status':<15}\n")
            f.write("-" * 100 + "\n")
            for c in certs:
                days_old = str(c['days_old']) if isinstance(c['days_old'], int) else '-'
                days_exp = str(c['days_until_expiry']) if isinstance(c['days_until_expiry'], int) else '-'
                f.write(f"{c['cn']:<40} {c['not_before']:<12} {c['not_after']:<12} {days_old:>10} {days_exp:>10} {c['status']:<15}\n")
        
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
        f.write(f"Target: {device.id_string()}\n")
        f.write(f"Safe: {counts['safe']} | Warnings: {counts['warning']} | Critical: {counts['critical']} | Info: {counts['info']}\n")
        if certs:
            expired = sum(1 for c in certs if c['status'] == 'EXPIRED')
            user_certs = sum(1 for c in certs if c['status'] == 'USER_CERT')
            f.write(f"Certificates: {len(certs)} total | {expired} expired | {user_certs} user-installed\n")
        f.write("=" * 40 + "\n")

    # CSV + HTML
    write_csv(csv_file, rows)
    write_html(html_file, device_info, rows, counts, certs)

    # Close SSH if used
    if isinstance(device, SSHDevice):
        device.close()

    # Summary output
    print(f"\n{Colors.CYAN}{'═' * 70}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BRIGHT_WHITE}✓ HARDAX AUDIT COMPLETED{Colors.RESET}")
    print(f"{Colors.CYAN}{'═' * 70}{Colors.RESET}")
    print(f"{Colors.BRIGHT_WHITE}📱 Target         : {Colors.BOLD}{Colors.BRIGHT_CYAN}{device.id_string()}{Colors.RESET}")
    print(f"{Colors.GREEN}✓  Safe Checks   : {Colors.BOLD}{counts['safe']}{Colors.RESET}")
    print(f"{Colors.YELLOW}⚠  Warnings      : {Colors.BOLD}{counts['warning']}{Colors.RESET}")
    print(f"{Colors.BRIGHT_RED}✗  Critical      : {Colors.BOLD}{counts['critical']}{Colors.RESET}")
    print(f"{Colors.BRIGHT_MAGENTA}?  Verify        : {Colors.BOLD}{counts['verify']}{Colors.RESET}")
    print(f"{Colors.CYAN}ℹ  Info          : {Colors.BOLD}{counts['info']}{Colors.RESET}")
    print(f"{Colors.CYAN}{'─' * 70}{Colors.RESET}")
    print(f"{Colors.DIM}📄 TXT Report    : {txt_file}{Colors.RESET}")
    print(f"{Colors.DIM}🌐 HTML Report   : {html_file}{Colors.RESET}")
    print(f"{Colors.DIM}📊 CSV Report    : {csv_file}{Colors.RESET}")
    print(f"{Colors.CYAN}{'═' * 70}{Colors.RESET}\n")


# =======================
# HARDAX v2 single-file enhancements
# - net-debug / net-strict via argv shim (env flags)
# - cert-debug / cert-limit via argv shim (env flags)
# - improved execute_with_p_fallback (preserve flags, drop -p only, tool swap)
# - improved certificate audit (APEX/Google dirs, PEM+DER via base64)
# =======================
import os, sys, base64

# ---- argv shim (strip our extra flags so argparse doesn't choke) ----
try:
    _clean = [sys.argv[0]]
    _i = 1
    while _i < len(sys.argv):
        a = sys.argv[_i]
        if a == '--net-debug':
            os.environ['HARDAX_NET_DEBUG'] = '1'
        elif a == '--net-strict':
            os.environ['HARDAX_NET_STRICT'] = '1'
        elif a == '--cert-debug':
            os.environ['HARDAX_CERT_DEBUG'] = '1'
        elif a == '--cert-limit':
            if _i + 1 < len(sys.argv):
                os.environ['HARDAX_CERT_LIMIT'] = sys.argv[_i+1]
                _i += 1
        else:
            _clean.append(a)
        _i += 1
    sys.argv = _clean
except Exception:
    pass

# ---- globals (for clarity; not strictly required) ----
NET_DEBUG = bool(os.environ.get('HARDAX_NET_DEBUG'))
NET_STRICT = bool(os.environ.get('HARDAX_NET_STRICT'))
CERT_DEBUG = bool(os.environ.get('HARDAX_CERT_DEBUG'))
try:
    CERT_LIMIT = int(os.environ.get('HARDAX_CERT_LIMIT', '50'))
except Exception:
    CERT_LIMIT = 50

# ---- helper: discover cert files in standard Android locations ----
def _find_cert_files(device):
    candidates = [
        '/system/etc/security/cacerts',
        '/system/etc/security/cacerts_google',
        '/apex/com.android.conscrypt/cacerts',
        '/apex/com.android.conscrypt/etc/security/cacerts',
    ]
    files = []
    for base in candidates:
        listing = device.shell(f'ls -1 {base} 2>/dev/null')
        names = [n.strip() for n in (listing.splitlines() if listing else []) if n.strip()]
        matched = []
        for name in names:
            if name.endswith('.0') or re.fullmatch(r'[0-9a-fA-F]{1,8}', name):
                matched.append(f"{base}/{name}")
        files.extend(matched)
        if CERT_DEBUG:
            try:
                print(f"[cert-debug] {base}: {len(matched)} files matched")
                for demo in matched[:5]:
                    print(f"  - {demo}")
            except Exception:
                pass
    return files

# ---- helper: robustly read cert bytes (PEM or DER) ----
def _read_cert_bytes(device, path):
    # 1) Try plain read to see if PEM
    txt = device.shell(f"cat {path} 2>/dev/null")
    if txt and '-----BEGIN CERTIFICATE-----' in txt:
        return txt.encode('utf-8'), 'PEM'
    # 2) Try base64 to obtain DER bytes safely
    b64 = device.shell(f"base64 {path} 2>/dev/null")
    if b64 and 'not found' not in b64.lower() and b64.strip():
        try:
            cleaned = ''.join(b64.strip().split())
            return base64.b64decode(cleaned, validate=False), 'DER'
        except Exception:
            return None, None
    return None, None

# ---- override: improved certificate audit ----
def audit_certificates(device: 'Device') -> List[Dict[str, Any]]:
    certs: List[Dict[str, Any]] = []
    try:
        from cryptography import x509
        from cryptography.hazmat.backends import default_backend
    except Exception:
        if CERT_DEBUG:
            print('[cert-debug] cryptography not available; skipping system cert parse')
        return []

    cert_files = _find_cert_files(device)
    if CERT_DEBUG:
        print(f"[cert-debug] discovered total: {len(cert_files)}")
    today = datetime.now()

    for i, cert_path in enumerate(cert_files[:CERT_LIMIT]):
        try:
            raw, kind = _read_cert_bytes(device, cert_path)
            if not raw:
                continue
            cert = None
            if kind == 'PEM':
                try:
                    cert = x509.load_pem_x509_certificate(raw, default_backend())
                except Exception:
                    cert = None
            if cert is None:
                try:
                    cert = x509.load_der_x509_certificate(raw, default_backend())
                except Exception:
                    cert = None
            if cert is None:
                if CERT_DEBUG:
                    print(f"[cert-debug] parse failed: {cert_path}")
                continue
            subject = getattr(cert, 'subject', None)
            issuer = getattr(cert, 'issuer', None)
            try:
                not_before = getattr(cert, 'not_valid_before')
                not_after = getattr(cert, 'not_valid_after')
            except Exception:
                # older libs
                not_before = getattr(cert, 'not_valid_before_utc', None)
                not_after = getattr(cert, 'not_valid_after_utc', None)
            if not_before is None or not_after is None:
                continue
            try:
                subject_str = subject.rfc4514_string() if subject else 'Unknown'
                issuer_str = issuer.rfc4514_string() if issuer else 'Unknown'
            except Exception:
                subject_str = 'Unknown'
                issuer_str = 'Unknown'
            days_old = (today - not_before.replace(tzinfo=None)).days
            days_until_expiry = (not_after.replace(tzinfo=None) - today).days
            if days_until_expiry < 0:
                status, risk = 'EXPIRED', 'critical'
            elif days_until_expiry < 30:
                status, risk = 'EXPIRING_SOON', 'warning'
            elif days_until_expiry < 90:
                status, risk = 'CHECK', 'warning'
            else:
                status, risk = 'VALID', 'safe'
            # CN extraction
            cn = 'Unknown'
            for part in subject_str.split(','):
                p = part.strip()
                if p.startswith('CN='):
                    cn = p[3:]
                    break
            certs.append({
                'filename': cert_path.split('/')[-1],
                'cn': cn[:50] + '...' if len(cn) > 50 else cn,
                'issuer': issuer_str[:50] + '...' if len(issuer_str) > 50 else issuer_str,
                'not_before': not_before.strftime('%Y-%m-%d'),
                'not_after': not_after.strftime('%Y-%m-%d'),
                'days_old': days_old,
                'days_until_expiry': days_until_expiry,
                'status': status,
                'risk': risk,
            })
        except Exception:
            continue

    # User-installed certs across all users
    try:
        user_roots = device.shell('ls -d /data/misc/user/*/cacerts-added 2>/dev/null')
        user_dirs = [d.strip() for d in (user_roots.split('\n') if user_roots else []) if d.strip()]
        if not user_dirs:
            user_dirs = ['/data/misc/user/0/cacerts-added']
        for d in user_dirs:
            ulist = device.shell(f'ls -1 {d} 2>/dev/null')
            if ulist.strip():
                for cf in [x.strip() for x in ulist.split('\n') if x.strip()]:
                    certs.append({
                        'filename': cf,
                        'cn': 'USER INSTALLED CERT',
                        'issuer': 'Unknown - User Added',
                        'not_before': '-',
                        'not_after': '-',
                        'days_old': 0,
                        'days_until_expiry': 0,
                        'status': 'USER_CERT',
                        'risk': 'critical',
                    })
    except Exception:
        pass

    return sorted(certs, key=lambda x: (x['risk'] != 'critical', x['risk'] != 'warning', x['days_until_expiry']))

# ---- override: execute_with_p_fallback (preserve flags; drop -p; swap tool) ----
def execute_with_p_fallback(device: 'Device', command: str, show_commands: bool = False, is_rooted: bool = None) -> str:
    def is_net_or_ss(cmd: str) -> bool:
        cl = cmd.lower()
        return ('netstat' in cl) or re.search(r'\bss\b', cl)

    def split_alternatives(src: str) -> list:
        s = re.sub(r"^\s*(?:/system/bin/)?sh\s+-[a-z]*c\s+(['\"])(.*?)\1\s*$", r"\2", src.strip(), flags=re.IGNORECASE)
        s = s.replace('\r\n', '\n').replace('\r', '\n')
        blocks = re.split(r'\n\s*\n+', s.strip())
        return [b for b in blocks if is_net_or_ss(b)]

    def split_pipeline(block: str):
        if '|' not in block:
            return block.strip(), ''
        base, rest = block.split('|', 1)
        return base.strip(), ('|' + rest.strip())

    def drop_pid_flag(cmd: str) -> str:
        def _rm_p(m):
            f = m.group(1)
            f2 = f.replace('p', '')
            return '-' + f2 if f2 else ''
        return re.sub(r'\s-(\w+)', _rm_p, cmd)

    def swap_tool(cmd: str):
        if re.match(r'(?i)^\s*netstat\b', cmd):
            return re.sub(r'(?i)^\s*netstat\b', 'ss', cmd, count=1)
        if re.match(r'(?i)^\s*ss\b', cmd):
            return re.sub(r'(?i)^\s*ss\b', 'netstat', cmd, count=1)
        return None

    def output_reason(txt: str):
        if not txt or not txt.strip():
            return False, 'empty output'
        lower = txt.lower()
        for bad in ['not found', 'invalid', 'permission denied', 'cannot open', 'no such']:
            if bad in lower:
                return False, bad
        lines = [l for l in txt.strip().split('\n') if l.strip()]
        if len(lines) <= 1 and (lines and ('proto' in lines[0].lower() or 'state' in lines[0].lower())):
            return False, 'header-only'
        return True, 'ok'

    # Bypass for non-network commands
    if not is_net_or_ss(command):
        if NET_DEBUG:
            print('[net-debug] non-network command -> bypass executor')
        return device.shell(command)

    blocks = split_alternatives(command)
    if NET_DEBUG:
        print('[net-debug] alternatives: %d block(s)' % len(blocks))
        for i, b in enumerate(blocks, 1):
            print('  block %d: %s' % (i, b.split('|')[0].strip()))
    if not blocks:
        return device.shell(command)

    for block in blocks:
        base_cmd, pipeline = split_pipeline(block)
        candidates = []
        if is_rooted or is_rooted is None:
            candidates.append('su -c "%s"' % base_cmd)
        candidates.append(base_cmd)
        # Without -p
        no_p = drop_pid_flag(base_cmd)
        if no_p != base_cmd:
            if is_rooted or is_rooted is None:
                candidates.append('su -c "%s"' % no_p)
            candidates.append(no_p)
        # Swap tool (preserve flags)
        swapped = swap_tool(base_cmd)
        if swapped:
            if is_rooted or is_rooted is None:
                candidates.append('su -c "%s"' % swapped)
            candidates.append(swapped)
            swapped_no_p = drop_pid_flag(swapped)
            if swapped_no_p != swapped:
                if is_rooted or is_rooted is None:
                    candidates.append('su -c "%s"' % swapped_no_p)
                candidates.append(swapped_no_p)

        if NET_DEBUG:
            print('[net-debug] candidates (%d):' % len(candidates))
            for c in candidates:
                print('  - %s' % c)

        for cand in candidates:
            if show_commands:
                print('  -> Trying: %s' % cand)
            raw = device.shell(cand)
            ok, why = output_reason(raw)
            if not ok:
                if NET_DEBUG:
                    print('[net-debug] reject: %s' % why)
                continue
            if NET_DEBUG:
                print('[net-debug] winner: %s' % cand)
            pipeline_src = (base_cmd + (' ' + pipeline if pipeline else ''))
            return apply_filters(raw, pipeline_src)

    return ''

# ======================= End v2 enhancements =======================

if __name__ == "__main__":
    main()
