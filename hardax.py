#!/usr/bin/env python3
"""
HARDAX - Hardening Audit eXaminer
Android & IoT Security Configuration Auditor

Modes:
    ADB (default)      -> runs commands via `adb shell`
    SSH (--mode ssh)   -> runs commands via SSH (password supported)

Features:
    Beautiful colored CLI output with real-time progress
    Live command execution display
    Enhanced visual feedback
    Collapsible HTML report with category sections

Reports:
    TXT + CSV + HTML (timestamped folders)
"""

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
from typing import List, Dict, Any, Tuple, Optional

__version__ = "2.0.0"

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
# Banner
# -------------------------

def print_banner(id_line: Optional[str]) -> None:
    """Print beautiful ASCII art banner with colors"""
    art = f"""{Colors.BRIGHT_CYAN}
  _    _          _____  _____      __   __
 | |  | |   /\\   |  __ \\|  __ \\   /\\ \\ / /
 | |__| |  /  \\  | |__) | |  | | /  \\\\ V / 
 |  __  | / /\\ \\ |  _  /| |  | |/ /\\ \\> <  
 | |  | |/ ____ \\| | \\ \\| |__| / ____ / . \\ 
 |_|  |_/_/    \\_\\_|  \\_\\_____/_/    \\_/ \\_\\{Colors.RESET}
"""
    print(art)
    print(f"{Colors.CYAN}{'═' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BRIGHT_WHITE}    HARDAX - Hardening Audit eXaminer{Colors.RESET}")
    print(f"{Colors.DIM}    Android & IoT Security Configuration Auditor v{__version__}{Colors.RESET}")
    print(f"{Colors.CYAN}{'═' * 60}{Colors.RESET}\n")
    
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

def write_html(html_path: str, device: Dict[str, str], rows: List[Dict[str, Any]], counts: Dict[str, int]) -> None:
    """Write modern HTML report with collapsible category sections"""
    
    # Group rows by category
    categories = {}
    for r in rows:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = {"rows": [], "stats": {"CRITICAL": 0, "WARNING": 0, "SAFE": 0, "INFO": 0}}
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
            css_class = {"SAFE": "safe", "WARNING": "warning", "CRITICAL": "critical"}.get(status, "info")
            
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
      --bg-primary: #f8fafc;
      --bg-secondary: #ffffff;
      --bg-tertiary: #f1f5f9;
      --text-primary: #1e293b;
      --text-secondary: #64748b;
      --border-color: #e2e8f0;
      --accent: #3b82f6;
      --critical: #ef4444;
      --warning: #f59e0b;
      --safe: #22c55e;
      --info: #3b82f6;
    }}
    
    body.dark {{
      --bg-primary: #0f172a;
      --bg-secondary: #1e293b;
      --bg-tertiary: #334155;
      --text-primary: #f1f5f9;
      --text-secondary: #94a3b8;
      --border-color: #334155;
    }}
    
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    
    body {{
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      line-height: 1.6;
      transition: background 0.3s, color 0.3s;
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
    
    body.dark pre {{ background: #0f172a; }}
    
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
        <button class="btn" onclick="toggleTheme()">🌙 Theme</button>
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
    
    <div id="categoriesContainer">
      {categories_html}
    </div>
    
    <footer>
      <p><strong>HARDAX</strong> - Hardening Audit eXaminer | Report generated: {time.strftime("%Y-%m-%d %H:%M:%S")}</p>
      <p>Android & IoT Security Configuration Auditor</p>
    </footer>
  </div>
  
  <script>
    // Theme toggle
    function toggleTheme() {{
      document.body.classList.toggle('dark');
      localStorage.setItem('hardax-theme', document.body.classList.contains('dark') ? 'dark' : 'light');
    }}
    
    // Load saved theme
    if (localStorage.getItem('hardax-theme') === 'dark') {{
      document.body.classList.add('dark');
    }}
    
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
          labels: ['Critical', 'Warning', 'Safe', 'Info'],
          datasets: [{{
            data: [{counts.get("critical", 0)}, {counts.get("warning", 0)}, {counts.get("safe", 0)}, {counts.get("info", 0)}],
            backgroundColor: ['#ef4444', '#f59e0b', '#22c55e', '#3b82f6'],
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

def run_checks(device: Device, checks: List[Dict[str, Any]], on_progress=None, show_commands: bool = False) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    rows: List[Dict[str, Any]] = []
    counts = {"safe": 0, "warning": 0, "critical": 0, "info": 0}
    total = len(checks)
    start_time = time.time()

    for idx, chk in enumerate(checks, start=1):
        category = chk.get("category", "General")
        label = chk.get("label", "Unnamed")
        command = chk.get("command", "")
        safe_pattern = chk.get("safe_pattern", "")
        level = chk.get("level", "info")
        desc = chk.get("description", "")

        raw = device.shell(command) if command else ""
        normalized = normalize_for_match(raw)
        bucket = bucket_from_level(level)

        matched = False
        if safe_pattern:
            try:
                matched = bool(re.search(safe_pattern, normalized, re.IGNORECASE | re.MULTILINE | re.DOTALL))
            except re.error:
                matched = safe_pattern.lower() in normalized.lower()

        if matched:
            status = "SAFE"
            counts["safe"] += 1
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

        rows.append({
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "category": category,
            "label": label,
            "level": level,
            "bucket": bucket,
            "status": status,
            "matched": str(matched),
            "command": command,
            "result": raw,
            "description": desc,
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
    device_info = collect_device_info(device)
    rows, counts = run_checks(device, checks, on_progress=_progress, show_commands=args.show_commands or not args.progress_numbers)

    if args.progress_numbers:
        print()

    # TXT Report
    with open(txt_file, "w", encoding="utf-8") as f:
        f.write(f"HARDAX - Hardening Audit eXaminer Report\nGenerated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write("Device Information\n" + "=" * 40 + "\n")
        for k in ["model", "brand", "manufacturer", "name", "soc_manufacturer", "soc_model",
                  "android_version", "sdk_level", "build_id", "fingerprint", "serialno", "timezone"]:
            f.write(f"{k.replace('_', ' ').title()}: {device_info.get(k, '')}\n")
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
        f.write("=" * 40 + "\n")

    # CSV + HTML
    write_csv(csv_file, rows)
    write_html(html_file, device_info, rows, counts)

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
    print(f"{Colors.CYAN}ℹ  Info          : {Colors.BOLD}{counts['info']}{Colors.RESET}")
    print(f"{Colors.CYAN}{'─' * 70}{Colors.RESET}")
    print(f"{Colors.DIM}📄 TXT Report    : {txt_file}{Colors.RESET}")
    print(f"{Colors.DIM}🌐 HTML Report   : {html_file}{Colors.RESET}")
    print(f"{Colors.DIM}📊 CSV Report    : {csv_file}{Colors.RESET}")
    print(f"{Colors.CYAN}{'═' * 70}{Colors.RESET}\n")

if __name__ == "__main__":
    main()
