#!/usr/bin/env python3
"""
CRISCAN - Critical Infrastructure Security Scanner (Python 3)
- Modes:
     ADB (default)      -> runs commands via `adb shell`
     SSH (--mode ssh)   -> runs commands via SSH (password supported)
- Features:
     Beautiful colored CLI output with real-time progress
     Live command execution display
     Enhanced visual feedback
- Reports:
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
    # Only normalize Windows line endings, don't collapse all newlines
    return (s or "").replace("\r\n", "\n").replace("\r", "\n")

def bucket_from_level(level: str) -> str:
    """
    FIX BUG-002: Added 'high' as distinct bucket
    """
    lvl = (level or "").strip().lower()
    if lvl == "critical":
        return "critical"
    if lvl == "high":
        return "high"  # FIX: high is now separate from critical
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
            import paramiko  # lazy import
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
   ____ ____  ___ ____   ____    _    _   _ 
  / ___|  _ \\|_ _/ ___| / ___|  / \\  | \\ | |
 | |   | |_) || |\\___ \\| |     / _ \\ |  \\| |
 | |___|  _ < | | ___) | |___ / ___ \\| |\\  |
  \\____|_| \\_\\___|____/ \\____/_/   \\_\\_| \\_|{Colors.RESET}
"""
    print(art)
    print(f"{Colors.CYAN}{'═' * 60}{Colors.RESET}")
    print(f"{Colors.BOLD}{Colors.BRIGHT_WHITE}    CRISCAN - Critical Infrastructure Security Scanner{Colors.RESET}")
    print(f"{Colors.DIM}    v2.0 - Enhanced & Fixed{Colors.RESET}")
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
    # Works best on Android; on generic Linux many fields will be "(unknown)"
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
            # Allow slightly different spellings by normalizing minimal fields
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
        # Natural-ish ordering by filename
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
    # Group checks by category
    from collections import OrderedDict
    categories = OrderedDict()
    for r in rows:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = {"checks": [], "safe": 0, "warning": 0, "critical": 0, "high": 0, "info": 0}
        categories[cat]["checks"].append(r)
        status = r["status"].lower()
        if status in categories[cat]:
            categories[cat][status] += 1
    
    # Build category sections
    category_html = []
    for cat_idx, (cat_name, cat_data) in enumerate(categories.items()):
        cat_id = f"cat_{cat_idx}"
        checks_html = []
        
        for r in cat_data["checks"]:
            cmd_esc = html_escape(r["command"])
            res_esc = html_escape(r["result"])
            desc_esc = html_escape(r["description"])
            label_esc = html_escape(r["label"])
            status = r["status"]
            css_class = {"SAFE": "safe", "WARNING": "warning", "CRITICAL": "critical", "HIGH": "high"}.get(status, "info")
            
            checks_html.append(f"""
        <div class="check-item">
          <div class="check-header">
            <span class="check-label">{label_esc}</span>
            <span class="status-badge {css_class}">{status}</span>
          </div>
          <div class="check-body">
            <p><strong>Description:</strong> {desc_esc}</p>
            <p><strong>Command:</strong></p>
            <pre><code>{cmd_esc}</code></pre>
            <p><strong>Result:</strong></p>
            <pre><code>{res_esc}</code></pre>
          </div>
        </div>""")
        
        # Category stats badges
        stats_badges = []
        if cat_data["critical"] > 0:
            stats_badges.append(f'<span class="cat-badge critical">{cat_data["critical"]} Critical</span>')
        if cat_data["high"] > 0:
            stats_badges.append(f'<span class="cat-badge high">{cat_data["high"]} High</span>')
        if cat_data["warning"] > 0:
            stats_badges.append(f'<span class="cat-badge warning">{cat_data["warning"]} Warning</span>')
        if cat_data["safe"] > 0:
            stats_badges.append(f'<span class="cat-badge safe">{cat_data["safe"]} Safe</span>')
        if cat_data["info"] > 0:
            stats_badges.append(f'<span class="cat-badge info">{cat_data["info"]} Info</span>')
        
        stats_html = " ".join(stats_badges)
        checks_content = "\n".join(checks_html)
        
        category_html.append(f"""
    <div class="category-section" id="{cat_id}">
      <div class="category-header" onclick="toggleCategory('{cat_id}')">
        <div class="category-title">
          <span class="toggle-icon">▶</span>
          <span class="category-name">{html_escape(cat_name)}</span>
          <span class="check-count">({len(cat_data["checks"])} checks)</span>
        </div>
        <div class="category-stats">{stats_html}</div>
      </div>
      <div class="category-content">
        {checks_content}
      </div>
    </div>""")
    
    categories_html = "\n".join(category_html)
    
    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CRISCAN - Security Audit Report</title>
  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <style>
    * {{ box-sizing: border-box; }}
    body {{ 
      font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, Roboto, "Helvetica Neue", sans-serif; 
      background: #f0f2f5; 
      padding: 20px; 
      margin: 0;
      transition: background 0.3s, color 0.3s;
      line-height: 1.6;
    }}
    
    .container {{ max-width: 1400px; margin: 0 auto; }}
    
    h1 {{ 
      color: #1a1a2e; 
      margin-bottom: 5px;
      font-size: 2.2em;
    }}
    h2 {{ 
      color: #16213e; 
      border-bottom: 3px solid #0f3460;
      padding-bottom: 10px;
      margin-top: 30px;
    }}
    
    /* Toolbar */
    #toolbar {{
      position: sticky;
      top: 0;
      z-index: 999;
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 15px 20px;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      border-radius: 12px;
      margin-bottom: 20px;
      box-shadow: 0 4px 15px rgba(0,0,0,0.2);
    }}
    #toolbar .logo {{ color: #fff; font-weight: bold; font-size: 1.3em; }}
    #toolbar .logo span {{ color: #e94560; }}
    .toolbar-controls {{ display: flex; gap: 10px; align-items: center; }}
    
    #searchInput {{
      width: 280px;
      padding: 10px 15px;
      border-radius: 8px;
      border: none;
      font-size: 14px;
      background: rgba(255,255,255,0.1);
      color: #fff;
    }}
    #searchInput::placeholder {{ color: rgba(255,255,255,0.6); }}
    #searchInput:focus {{ outline: none; background: rgba(255,255,255,0.2); }}
    
    .btn {{
      padding: 10px 18px;
      border-radius: 8px;
      border: none;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.2s;
      font-size: 13px;
    }}
    .btn-primary {{ background: #e94560; color: #fff; }}
    .btn-primary:hover {{ background: #ff6b6b; transform: translateY(-1px); }}
    .btn-secondary {{ background: rgba(255,255,255,0.15); color: #fff; }}
    .btn-secondary:hover {{ background: rgba(255,255,255,0.25); }}
    
    /* Summary Cards */
    .summary-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
      gap: 15px;
      margin: 20px 0;
    }}
    .summary-card {{
      background: #fff;
      border-radius: 12px;
      padding: 20px;
      text-align: center;
      box-shadow: 0 2px 10px rgba(0,0,0,0.08);
      border-left: 5px solid #ccc;
    }}
    .summary-card.critical {{ border-left-color: #e53935; }}
    .summary-card.high {{ border-left-color: #ff9800; }}
    .summary-card.warning {{ border-left-color: #fdd835; }}
    .summary-card.safe {{ border-left-color: #43a047; }}
    .summary-card.info {{ border-left-color: #1e88e5; }}
    .summary-card .count {{ font-size: 2.5em; font-weight: bold; }}
    .summary-card .label {{ color: #666; font-size: 0.9em; text-transform: uppercase; }}
    .summary-card.critical .count {{ color: #e53935; }}
    .summary-card.high .count {{ color: #ff9800; }}
    .summary-card.warning .count {{ color: #f9a825; }}
    .summary-card.safe .count {{ color: #43a047; }}
    .summary-card.info .count {{ color: #1e88e5; }}
    
    /* Device Info */
    .device-info {{
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: #fff;
      border-radius: 12px;
      padding: 25px;
      margin: 20px 0;
    }}
    .device-info h3 {{ margin-top: 0; border-bottom: 1px solid rgba(255,255,255,0.3); padding-bottom: 10px; }}
    .device-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
      gap: 10px;
    }}
    .device-item {{ padding: 5px 0; }}
    .device-item strong {{ opacity: 0.8; }}
    
    /* Category Sections */
    .category-section {{
      background: #fff;
      border-radius: 12px;
      margin-bottom: 15px;
      overflow: hidden;
      box-shadow: 0 2px 10px rgba(0,0,0,0.08);
    }}
    
    .category-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 18px 20px;
      background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
      cursor: pointer;
      transition: background 0.2s;
      flex-wrap: wrap;
      gap: 10px;
    }}
    .category-header:hover {{
      background: linear-gradient(135deg, #e9ecef 0%, #dee2e6 100%);
    }}
    
    .category-title {{
      display: flex;
      align-items: center;
      gap: 12px;
    }}
    
    .toggle-icon {{
      font-size: 12px;
      transition: transform 0.3s;
      color: #666;
    }}
    .category-section.expanded .toggle-icon {{
      transform: rotate(90deg);
    }}
    
    .category-name {{
      font-weight: 700;
      font-size: 1.1em;
      color: #1a1a2e;
    }}
    
    .check-count {{
      color: #666;
      font-size: 0.9em;
    }}
    
    .category-stats {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }}
    
    .cat-badge {{
      padding: 4px 10px;
      border-radius: 20px;
      font-size: 11px;
      font-weight: 600;
    }}
    .cat-badge.critical {{ background: #ffebee; color: #c62828; }}
    .cat-badge.high {{ background: #fff3e0; color: #e65100; }}
    .cat-badge.warning {{ background: #fffde7; color: #f9a825; }}
    .cat-badge.safe {{ background: #e8f5e9; color: #2e7d32; }}
    .cat-badge.info {{ background: #e3f2fd; color: #1565c0; }}
    
    .category-content {{
      display: none;
      padding: 0;
    }}
    .category-section.expanded .category-content {{
      display: block;
    }}
    
    /* Individual Check Items */
    .check-item {{
      border-bottom: 1px solid #eee;
      padding: 20px;
    }}
    .check-item:last-child {{
      border-bottom: none;
    }}
    
    .check-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 15px;
    }}
    
    .check-label {{
      font-weight: 600;
      font-size: 1.05em;
      color: #333;
    }}
    
    .status-badge {{
      padding: 6px 14px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
    }}
    .status-badge.safe {{ background: #e8f5e9; color: #2e7d32; }}
    .status-badge.warning {{ background: #fffde7; color: #f57f17; }}
    .status-badge.high {{ background: #fff3e0; color: #e65100; }}
    .status-badge.critical {{ background: #ffebee; color: #c62828; }}
    .status-badge.info {{ background: #e3f2fd; color: #1565c0; }}
    
    .check-body p {{
      margin: 10px 0;
      color: #555;
    }}
    
    pre {{
      background: #1a1a2e;
      color: #a5d6a7;
      padding: 15px;
      border-radius: 8px;
      overflow-x: auto;
      font-size: 13px;
      font-family: "Fira Code", "Consolas", monospace;
      max-height: 200px;
    }}
    
    /* Chart Container */
    .chart-container {{
      background: #fff;
      border-radius: 12px;
      padding: 20px;
      box-shadow: 0 2px 10px rgba(0,0,0,0.08);
      max-width: 350px;
    }}
    
    /* Footer */
    footer {{
      text-align: center;
      padding: 30px;
      color: #666;
      margin-top: 40px;
    }}
    
    /* Dark Theme */
    body.dark {{
      background: #0f0f1a;
      color: #e0e0e0;
    }}
    body.dark h1, body.dark h2 {{ color: #fff; }}
    body.dark h2 {{ border-bottom-color: #e94560; }}
    body.dark .category-section {{ background: #1a1a2e; }}
    body.dark .category-header {{ background: linear-gradient(135deg, #16213e 0%, #1a1a2e 100%); }}
    body.dark .category-header:hover {{ background: linear-gradient(135deg, #1a1a2e 0%, #252540 100%); }}
    body.dark .category-name {{ color: #fff; }}
    body.dark .check-item {{ border-bottom-color: #2a2a4a; }}
    body.dark .check-label {{ color: #fff; }}
    body.dark .check-body p {{ color: #aaa; }}
    body.dark .summary-card {{ background: #1a1a2e; }}
    body.dark .summary-card .label {{ color: #aaa; }}
    body.dark .chart-container {{ background: #1a1a2e; }}
    body.dark pre {{ background: #0a0a15; }}
    body.dark footer {{ color: #888; }}
    
    /* Responsive */
    @media (max-width: 768px) {{
      #toolbar {{ flex-direction: column; gap: 15px; }}
      .toolbar-controls {{ width: 100%; justify-content: center; flex-wrap: wrap; }}
      #searchInput {{ width: 100%; }}
      .category-header {{ flex-direction: column; align-items: flex-start; }}
    }}
  </style>
</head>
<body>
<div class="container">

<div id="toolbar">
  <div class="logo">CRIS<span>CAN</span></div>
  <div class="toolbar-controls">
    <input id="searchInput" type="text" placeholder="🔍 Search checks...">
    <button class="btn btn-secondary" onclick="expandAll()">Expand All</button>
    <button class="btn btn-secondary" onclick="collapseAll()">Collapse All</button>
    <button class="btn btn-primary" onclick="toggleTheme()">🌙 Theme</button>
  </div>
</div>

<h1>🛡️ Security Audit Report</h1>
<p style="color:#666;margin-top:0;">Generated: {time.strftime("%Y-%m-%d %H:%M:%S")}</p>

<div class="summary-grid">
  <div class="summary-card critical">
    <div class="count">{counts["critical"]}</div>
    <div class="label">Critical</div>
  </div>
  <div class="summary-card high">
    <div class="count">{counts["high"]}</div>
    <div class="label">High</div>
  </div>
  <div class="summary-card warning">
    <div class="count">{counts["warning"]}</div>
    <div class="label">Warning</div>
  </div>
  <div class="summary-card safe">
    <div class="count">{counts["safe"]}</div>
    <div class="label">Safe</div>
  </div>
  <div class="summary-card info">
    <div class="count">{counts["info"]}</div>
    <div class="label">Info</div>
  </div>
</div>

<div style="display:flex;gap:30px;flex-wrap:wrap;align-items:flex-start;">
  <div class="device-info" style="flex:1;min-width:300px;">
    <h3>📱 Device Information</h3>
    <div class="device-grid">
      <div class="device-item"><strong>Model:</strong> {html_escape(device.get("model","N/A"))}</div>
      <div class="device-item"><strong>Brand:</strong> {html_escape(device.get("brand","N/A"))}</div>
      <div class="device-item"><strong>Manufacturer:</strong> {html_escape(device.get("manufacturer","N/A"))}</div>
      <div class="device-item"><strong>Android:</strong> {html_escape(device.get("android_version","N/A"))}</div>
      <div class="device-item"><strong>SDK:</strong> {html_escape(device.get("sdk_level","N/A"))}</div>
      <div class="device-item"><strong>Build:</strong> {html_escape(device.get("build_id","N/A"))}</div>
      <div class="device-item"><strong>Serial:</strong> {html_escape(device.get("serialno","N/A"))}</div>
      <div class="device-item"><strong>SoC:</strong> {html_escape(device.get("soc_model","N/A"))}</div>
    </div>
  </div>
  <div class="chart-container">
    <canvas id="summaryChart" width="300" height="300"></canvas>
  </div>
</div>

<h2>📋 Security Findings ({len(rows)} checks in {len(categories)} categories)</h2>

{categories_html}

<footer>
  <strong>CRISCAN</strong> - Critical Infrastructure Security Scanner v2.0<br>
  <small>Total Checks: {len(rows)} | Categories: {len(categories)}</small>
</footer>

</div>

<script>
// Toggle category
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

// Theme toggle
function toggleTheme() {{
  document.body.classList.toggle('dark');
  localStorage.setItem('theme', document.body.classList.contains('dark') ? 'dark' : 'light');
}}

// Load saved theme
if (localStorage.getItem('theme') === 'dark') {{
  document.body.classList.add('dark');
}}

// Search
document.getElementById("searchInput").addEventListener("input", function() {{
  let query = this.value.trim().toLowerCase();
  
  document.querySelectorAll('.category-section').forEach(function(cat) {{
    let hasMatch = false;
    cat.querySelectorAll('.check-item').forEach(function(check) {{
      let text = check.innerText.toLowerCase();
      if (query === "" || text.includes(query)) {{
        check.style.display = "";
        hasMatch = true;
      }} else {{
        check.style.display = "none";
      }}
    }});
    
    if (query !== "") {{
      if (hasMatch) {{
        cat.style.display = "";
        cat.classList.add('expanded');
      }} else {{
        cat.style.display = "none";
      }}
    }} else {{
      cat.style.display = "";
    }}
  }});
}});

// Chart
window.addEventListener('load', function() {{
  var ctx = document.getElementById("summaryChart").getContext("2d");
  new Chart(ctx, {{
    type: "doughnut",
    data: {{
      labels: ["Critical", "High", "Warning", "Safe", "Info"],
      datasets: [{{
        data: [{counts["critical"]}, {counts["high"]}, {counts["warning"]}, {counts["safe"]}, {counts["info"]}],
        backgroundColor: ["#e53935", "#ff9800", "#fdd835", "#43a047", "#1e88e5"],
        borderWidth: 0
      }}]
    }},
    options: {{
      responsive: true,
      cutout: '60%',
      plugins: {{
        legend: {{ position: "bottom", labels: {{ padding: 15 }} }}
      }}
    }}
  }});
}});
</script>
</body>
</html>"""
    
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(doc)

# -------------------------
# Engine
# -------------------------

def validate_check_pattern(check: Dict[str, Any]) -> List[str]:
    """Validate check patterns for common issues that cause false positives"""
    issues = []
    pattern = check.get('safe_pattern', '')
    label = check.get('label', 'Unknown')
    level = check.get('level', 'info')
    
    # Check for overly broad patterns in critical/warning checks
    if pattern == '.*':
        if level not in ['info', 'safe']:
            issues.append(f"WARNING [{label}]: Catch-all pattern '.*' in {level} check - will match errors as SAFE")
    
    # Check for missing stderr redirection in commands with common issues
    command = check.get('command', '')
    risky_commands = ['ls ', 'cat ', 'find ', 'getprop ']
    if any(cmd in command for cmd in risky_commands):
        if '2>/dev/null' not in command and '2>&1' not in command:
            issues.append(f"INFO [{label}]: Command may need stderr redirection (2>/dev/null)")
    
    # Test pattern compilation - FIX BUG-003: Now reports errors
    try:
        re.compile(pattern)
    except re.error as e:
        issues.append(f"ERROR [{label}]: Invalid regex pattern: {e}")
    
    return issues

def run_checks(device: Device, checks: List[Dict[str, Any]], on_progress=None, show_commands=False) -> Tuple[List[Dict[str, Any]], Dict[str, int]]:
    rows = []
    # FIX BUG-004: Added 'info' and 'high' to counts
    counts = {"safe": 0, "warning": 0, "high": 0, "critical": 0, "info": 0}
    total = len(checks)
    start_time = time.time()

    for idx, chk in enumerate(checks, start=1):
        category = chk["category"]
        label = chk["label"]
        command = chk["command"]
        safe_pattern = chk["safe_pattern"]
        level = chk.get("level", "info")
        desc = chk.get("description", "")

        # Execute command
        raw = device.shell(command).strip()
        
        # FIX BUG-001: Don't treat empty output as [Not Supported]
        # Empty output is often the EXPECTED result (e.g., grep finding nothing)
        # Only mark as [Not Supported] for actual errors
        is_error = raw.startswith("[SSH Error]") or raw.startswith("[ADB Error]")
        
        if is_error:
            raw = "[Not Supported]"

        match_src = normalize_for_match(raw)
        regex_error = None
        try:
            matched = bool(re.search(safe_pattern, match_src, flags=re.DOTALL))
        except re.error as e:
            matched = False
            regex_error = str(e)
            # FIX BUG-003: Log regex errors
            print(f"{Colors.BRIGHT_RED}REGEX ERROR [{label}]: {e}{Colors.RESET}", file=sys.stderr)

        if raw == "[Not Supported]":
            status = "INFO"
            bucket = "info"
            counts["info"] += 1  # FIX: Count INFO
        elif matched:
            status = "SAFE"
            bucket = "info"
            counts["safe"] += 1
        else:
            bucket = bucket_from_level(level)
            if bucket == "critical":
                status = "CRITICAL"
                counts["critical"] += 1
            elif bucket == "high":  # FIX BUG-002: High is now separate
                status = "HIGH"
                counts["high"] += 1
            elif bucket == "warning":
                status = "WARNING"
                counts["warning"] += 1
            else:
                status = "INFO"
                counts["info"] += 1  # FIX: Count INFO

        # Colorful progress display
        if on_progress:
            try:
                # Calculate progress
                percentage = (idx / total) * 100
                elapsed = time.time() - start_time
                if idx > 0:
                    eta = (elapsed / idx) * (total - idx)
                    eta_str = time.strftime("%M:%S", time.gmtime(eta))
                else:
                    eta_str = "--:--"
                
                # Status color and symbol
                if status == "SAFE":
                    status_color = Colors.GREEN
                    status_symbol = "✓"
                elif status == "CRITICAL":
                    status_color = Colors.BRIGHT_RED
                    status_symbol = "✗"
                elif status == "HIGH":
                    status_color = Colors.BRIGHT_MAGENTA
                    status_symbol = "!"
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
                
                # Clear line and print progress
                print(f"\r{Colors.CYAN}[{idx:3d}/{total:3d}]{Colors.RESET} "
                      f"{Colors.BRIGHT_BLUE}[{bar}]{Colors.RESET} "
                      f"{Colors.BRIGHT_WHITE}{percentage:5.1f}%{Colors.RESET} "
                      f"{Colors.DIM}ETA: {eta_str}{Colors.RESET}", end='', flush=True)
                
                # Show current check on new line if commands enabled
                if show_commands:
                    print()  # New line
                    
                    # Truncate label if too long
                    label_display = label[:50] + "..." if len(label) > 50 else label
                    
                    print(f"  {Colors.BRIGHT_CYAN}▶{Colors.RESET} {Colors.BOLD}{label_display}{Colors.RESET} "
                          f"{status_color}[{status_symbol} {status}]{Colors.RESET}")
                    
                    # Show command
                    cmd_display = command[:70] + "..." if len(command) > 70 else command
                    print(f"    {Colors.DIM}$ {cmd_display}{Colors.RESET}", flush=True)
                
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
    
    # Final newline after progress
    print()
    
    return rows, counts

# -------------------------
# Main
# -------------------------

def main():
    ap = argparse.ArgumentParser(description="CRISCAN - Critical Infrastructure Security Scanner")
    ap.add_argument("--mode", choices=["adb", "ssh"], default="adb", help="How to run commands (default: adb)")
    # ADB
    ap.add_argument("--json", help="Path to single commands JSON (list or {checks: [...]})")
    ap.add_argument("--json-dir", help="Folder with *.json files to merge")
    ap.add_argument("--serial", default=os.environ.get("ANDROID_SERIAL", ""), help="ADB serial (or set ANDROID_SERIAL)")
    # SSH
    ap.add_argument("--host", help="SSH host (required for --mode ssh)")
    ap.add_argument("--port", type=int, default=22, help="SSH port (default: 22)")
    ap.add_argument("--ssh-user", help="SSH username")
    ap.add_argument("--ssh-pass", help="SSH password")
    # Output
    ap.add_argument("--out", default="android_audit_output", help="Output directory (default: android_audit_output)")
    ap.add_argument("--progress-numbers", action="store_true", help="Show live progress with X/Y counter")
    ap.add_argument("--show-commands", action="store_true", help="Display each command as it executes (colorful progress)")

    args = ap.parse_args()

    # Load checks (must be before device work to know total for progress)
    checks = load_checks(args.json, args.json_dir)
    
    # Pattern validation disabled for cleaner output
    # Validation is done at development time, not runtime


    # Device selection / connection
    device: Device = None
    try:
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

        # Progress callback (numbers only, single location via carriage return)
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

        # Collect + run
        print(f"\n{Colors.BRIGHT_CYAN}🔍 Starting security audit...{Colors.RESET}\n")
        device_info = collect_device_info(device)
        rows, counts = run_checks(device, checks, on_progress=_progress, show_commands=args.show_commands or not args.progress_numbers)

        # newline after progress stream
        if args.progress_numbers:
            print()

        # TXT
        with open(txt_file, "w", encoding="utf-8") as f:
            f.write(f"CRISCAN - Security Audit Report\nGenerated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            f.write("Device Information\n")
            for k in ["model", "brand", "manufacturer", "name", "soc_manufacturer", "soc_model",
                      "android_version", "sdk_level", "build_id", "fingerprint", "serialno", "timezone"]:
                f.write(f"{k.replace('_', ' ').title()}: {device_info.get(k, '')}\n")
            f.write("\nFindings\n")
            for r in rows:
                f.write("\n")
                f.write(f"# === {r['category']} ===\n")
                f.write(f"Check: {r['label']}\n")
                f.write(f"Command: {r['command']}\n")
                f.write(f"Description: {r['description']}\n")
                f.write("Result:\n")
                f.write(r["result"] + "\n")
                f.write(f"Status: {r['status']}\n")

            f.write("\n======================================\n")
            f.write("ANDROID/LINUX AUDIT COMPLETED\n")
            f.write(f"Target              : {device.id_string()}\n")
            f.write(f"Safe Checks        : {counts['safe']}\n")
            f.write(f"Warnings           : {counts['warning']}\n")
            f.write(f"High Issues        : {counts['high']}\n")
            f.write(f"Critical Issues    : {counts['critical']}\n")
            f.write(f"Info               : {counts['info']}\n")
            f.write(f"TXT Report         : {txt_file}\n")
            f.write(f"HTML Report        : {html_file}\n")
            f.write(f"CSV Report         : {csv_file}\n")
            f.write("======================================\n")

        # CSV + HTML
        write_csv(csv_file, rows)
        write_html(html_file, device_info, rows, counts)

        # Beautiful summary output
        print(f"\n{Colors.CYAN}{'═' * 70}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.BRIGHT_WHITE}✓ AUDIT COMPLETED{Colors.RESET}")
        print(f"{Colors.CYAN}{'═' * 70}{Colors.RESET}")
        print(f"{Colors.BRIGHT_WHITE}📱 Target         : {Colors.BOLD}{Colors.BRIGHT_CYAN}{device.id_string()}{Colors.RESET}")
        print(f"{Colors.GREEN}✓  Safe Checks   : {Colors.BOLD}{counts['safe']}{Colors.RESET}")
        print(f"{Colors.YELLOW}⚠  Warnings      : {Colors.BOLD}{counts['warning']}{Colors.RESET}")
        print(f"{Colors.BRIGHT_MAGENTA}!  High          : {Colors.BOLD}{counts['high']}{Colors.RESET}")
        print(f"{Colors.BRIGHT_RED}✗  Critical      : {Colors.BOLD}{counts['critical']}{Colors.RESET}")
        print(f"{Colors.CYAN}ℹ  Info          : {Colors.BOLD}{counts['info']}{Colors.RESET}")
        print(f"{Colors.CYAN}{'─' * 70}{Colors.RESET}")
        print(f"{Colors.DIM}📄 TXT Report    : {txt_file}{Colors.RESET}")
        print(f"{Colors.DIM}🌐 HTML Report   : {html_file}{Colors.RESET}")
        print(f"{Colors.DIM}📊 CSV Report    : {csv_file}{Colors.RESET}")
        print(f"{Colors.CYAN}{'═' * 70}{Colors.RESET}\n")

    finally:
        # FIX BUG-005: SSH cleanup in finally block
        if device and isinstance(device, SSHDevice):
            device.close()

if __name__ == "__main__":
    main()
