<h1 align="center">HARDAX</h1>


<p align="center">
  <img src="https://img.shields.io/badge/version-3.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.11+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/checks-619-orange.svg" alt="Checks">
  <img src="https://img.shields.io/badge/categories-19-purple.svg" alt="Categories">
  <img src="https://img.shields.io/badge/license-MIT-red.svg" alt="License">
  <a href="https://github.com/V33RU/hardax/wiki">
    <img src="https://img.shields.io/badge/wiki-documentation-lightgrey.svg" alt="Wiki">
  </a>
</p>

<p align="center">
</p>

![](https://raw.githubusercontent.com/V33RU/my-slides/refs/heads/main/images/report.png)

---

## Overview

**HARDAX** (Hardening Audit eXaminer) is a comprehensive security configuration auditor for Android-based devices. It performs **619 security checks** across **19 categories** to identify misconfigurations, vulnerabilities, and security weaknesses.

HARDAX is designed for:
- **Security Researchers** - Penetration testing and vulnerability assessment
- **IoT Security Teams** - Auditing Android-based IoT devices
- **POS Security Auditors** - PCI-DSS compliance verification for payment terminals
- **Enterprise Security** - MDM compliance verification
- **Developers** - Pre-release security validation

---

## What's New in v3.0

| Change | Details |
|--------|---------|
| **619 Security Checks** | Up from 539 - 80 new checks added across all categories |
| **Bluetooth Expansion** | Bluetooth checks expanded from 29 to 101 - covers BLE, Classic, PAN, PBAP, HFP, HSP, A2DP, AVRCP, HID, HOGP, SPP, OPP, MAP, GAP, ATT, SMP, L2CAP profiles and attack surfaces |
| **SSH Root Detection** | Distinguishes `ssh-root` (running as root directly) from `su`-based root - no false "su needed" messages |
| **False Positive Prevention** | `isEmptyOrError()` now catches `"Can't find service: <name>"` from `dumpsys` - unavailable services are marked SKIPPED instead of CRITICAL |
| **Certificate Audit Expanded** | Certificate audit checks increased from 11 to 27 |
| **Forensic Indicators Expanded** | Forensic checks increased from 11 to 24 |
| **Malware Detection Expanded** | Malware checks increased from 16 to 18 |
| **Code Cleanup** | Removed AI-generated Unicode markers (em dashes, box-drawing chars) from all comments |

---

## Features

| Feature | Description |
|---------|-------------|
| **619 Security Checks** | Comprehensive coverage across 19 security categories |
| **POS/Payment Terminal Support** | 24 PCI-DSS focused checks for payment devices |
| **Malware & Hooking Detection** | 18 checks for rootkits, RATs, Frida, Xposed, keyloggers, memory scrapers |
| **Certificate Audit** | CA certificate analysis with expiry/age calculation - 27 checks |
| **No Root Required** | Runs entirely via ADB shell commands |
| **Root Auto-Detection** | Detects root method (Magisk/SuperSU/su/ssh-root) and adapts privilege escalation accordingly |
| **ADB Resilience** | 5-layer protection: connection check, auto-reconnect, timeout, SKIPPED status |
| **Dual Connection Modes** | ADB (USB/Network) and SSH support |
| **SSH Root Awareness** | Detects when SSH session is already root - skips unnecessary `su` probing |
| **6 Status Levels** | SAFE, WARNING, CRITICAL, VERIFY, INFO, SKIPPED |
| **3 Report Formats** | TXT, CSV, HTML with interactive dashboard |
| **Smart False Positive Prevention** | Catches empty output, service unavailability, and transport errors - marks as SKIPPED not CRITICAL |
| **Extensible JSON Checks** | Easy to add custom security checks - drop JSON, run |
| **Beautiful CLI Output** | Color-coded real-time progress display |
| **Device Info Collection** | Automatic device fingerprinting |
| **Shell Environment Probe** | SSH mode probes busybox, toybox, getprop, bash availability on connect |

---

## Supported Devices

HARDAX works with any Android-based device accessible via ADB or SSH:

| Device Type | Examples |
|-------------|----------|
| **POS Terminals** | PAX, Verifone, Ingenico, Sunmi, Newland, Clover, Square |
| **Smartphones & Tablets** | Samsung, Pixel, OnePlus, Xiaomi, etc. |
| **IoT Devices** | Android Things, AOSP-based smart devices |
| **Collaboration Panels** | Poly, Neat, Webex Board |
| **Android Automotive** | Infotainment systems, head units |
| **Medical Devices** | Android-based clinical devices |
| **Industrial Android** | Rugged tablets, handheld scanners |
| **Android TV** | Smart TVs, set-top boxes |
| **Wearables** | Wear OS devices |

---

## Installation

### Prerequisites

- Python 3.11 or higher
- ADB (Android Debug Bridge) installed and in PATH
- USB Debugging enabled on target device

### Quick Start

```bash
# Clone the repository
git clone https://github.com/iotsrg/hardax.git
cd hardax

# Connect your device via USB
adb devices

# Run HARDAX
python3 hardax.py
```

### Optional Dependencies

```bash
# For Linux
pip install paramiko cryptography

# For Windows
py -m pip install -r requirements.txt
```

---

## Usage

### Basic Usage (ADB)

```bash
# Auto-detect connected device
python3 hardax.py

# Show commands being executed
python3 hardax.py --show-commands

# Load all check files from commands/ directory
python3 hardax.py --json-dir commands

# Specify device by serial
python3 hardax.py --serial DEVICE_SERIAL

# Custom output directory
python3 hardax.py --out ./my_reports

# Skip certificate audit
python3 hardax.py --skip-certs
```

### SSH Mode (Network)

```bash
python3 hardax.py --mode ssh --host 192.168.1.100 --ssh-user root --ssh-pass password
```

### Network ADB

```bash
adb connect 192.168.1.100:5555
python3 hardax.py --json-dir commands
```

### All Options

```
usage: hardax.py [OPTIONS]

Options:
  --version             Show version
  --mode {adb,ssh}      Connection mode (default: adb)
  --serial SERIAL       ADB device serial number
  --host HOST           SSH hostname/IP
  --port PORT           SSH port (default: 22)
  --ssh-user USER       SSH username
  --ssh-pass PASS       SSH password
  --json FILE           Path to single JSON checks file
  --json-dir DIR        Directory with JSON check files
  --out DIR             Output directory (default: hardax_output)
  --progress-numbers    Show numeric progress counter
  --show-commands       Display each command being executed
  --skip-certs          Skip certificate audit

Hidden debug flags (prefix before other args):
  --net-debug           Verbose network check output
  --net-strict          Strict network check mode
  --cert-debug          Verbose certificate audit output
  --cert-limit N        Limit certificate files scanned (default: 50)
```

---

## Security Categories

HARDAX organizes **619 checks** into **19 security categories**:

| Category | Checks | Description |
|----------|--------|-------------|
| **SYSTEM** | 89 | Kernel, memory, TEE, time, power, build properties, emulator detection, SIM status |
| **BLUETOOTH** | 101 | BLE/Classic, pairing, profiles (PAN, HFP, A2DP, HID, SPP, OPP, MAP), L2CAP, ATT, SMP, GAP, attack surfaces |
| **NETWORK** | 74 | Ports, WiFi, cellular, VPN, MQTT, CoAP, CAN bus, HL7, DICOM, active connections |
| **APPS** | 52 | Permissions, overlay attacks, installation sources, backup audit, dangerous perms |
| **PRIVACY** | 51 | Biometrics, screen lock, location, sensors, clipboard, audio |
| **CERTIFICATE_AUDIT** | 27 | CA certificates, user certs, pinning bypass, keystore, expiry analysis |
| **SELINUX** | 25 | SELinux enforcement, policy, audit, context, boot flags |
| **FORENSIC_INDICATORS** | 24 | Crash history, kernel panics, logcat anomalies, temp artifacts, clipboard forensics |
| **STORAGE** | 24 | Filesystem, backup, encryption, partitions |
| **POS_SECURITY** | 24 | PCI-DSS compliance, payment apps, kiosk mode, RAM scraper, NFC relay, PAX CVE |
| **BOOT_SECURITY** | 22 | Verified boot, AVB, dm-verity, bootloader, integrity |
| **CIS_BENCHMARK** | 20 | CIS Android Benchmark v1.6.0 controls (89% coverage) |
| **CRYPTOGRAPHY** | 19 | Encryption, keys, credentials, API keys, certificates |
| **MALWARE** | 18 | Root/Magisk/SuperSU, Frida, Xposed/LSPosed, RATs, keyloggers, memory scrapers, root cloaking |
| **USB_SECURITY** | 16 | USB debugging, interfaces, serial ports, gadget mode |
| **DEVICE_MANAGEMENT** | 13 | MDM, accounts, developer options |
| **INPUT** | 9 | Keyboards, accessibility, input methods |
| **NFC_SECURITY** | 7 | NFC state, Android Beam, tap-to-pay, reader mode, secure element (eSE/UICC) |
| **ADB_SECURITY** | 4 | ADB keys, network ADB, debugging |

---

## HTML Report Features

The interactive HTML report includes:

- **Summary Dashboard** - Total checks, pass/fail counts, doughnut chart
- **Device Information** - Model, Android version, build, serial, security patch level
- **Collapsible Categories** - Click to expand/collapse each security area
- **Color-Coded Results** - Green=SAFE, Yellow=WARNING, Red=CRITICAL
- **Certificate Audit Table** - CA certificates with expiry dates and risk status
- **Search & Filter** - Find specific checks by keyword
- **Category Statistics** - Per-category breakdown of findings

---

## Extending HARDAX

### Adding Custom Checks

Create or modify JSON files in the `commands/` directory:

```json
{
  "checks": [
    {
      "category": "CUSTOM",
      "label": "My Custom Port Check",
      "command": "netstat -tlnp 2>/dev/null | grep ':8080'",
      "safe_pattern": "^$",
      "level": "warning",
      "description": "Check if port 8080 is open",
      "empty_is_safe": true
    }
  ]
}
```

### JSON Check Fields

| Field | Required | Description |
|-------|----------|-------------|
| `category` | Yes | Category name (e.g. SYSTEM, NETWORK) |
| `label` | Yes | Human-readable check name |
| `command` | Yes | Shell command to run on device |
| `safe_pattern` | Yes | Regex pattern that indicates a safe result |
| `level` | Yes | Severity: `info`, `warning`, `high`, `critical` |
| `description` | Yes | What the check detects |
| `empty_is_safe` | No | If true, empty output = SAFE |
| `why` | No | Explanation of why this matters |
| `risk_if_fail` | No | What risk the failure represents |
| `nist_800_53` | No | Relevant NIST 800-53 control IDs |
| `id` | No | Unique check identifier (e.g. BT-001) |

---

## Project Structure

```
HARDAX/
├── hardax.py              # Main engine (1746 lines)
├── requirements.txt       # Python dependencies
├── README.md              # This file
├── templates/             # Report templates
│   └── report.html        # Interactive HTML report template
└── commands/              # Security check definitions
    ├── system.json        #  89 checks - Kernel, TEE, build, emulator, memory
    ├── bluetooth.json     # 101 checks - BLE/Classic, pairing, all profiles
    ├── network.json       #  74 checks - Ports, WiFi, VPN, IoT protocols
    ├── apps.json          #  52 checks - Permissions, overlay, backup, install
    ├── privacy.json       #  51 checks - Biometrics, location, sensors
    ├── certificate_audit.json # 27 checks - CA certs, expiry, MITM
    ├── forensic_indicators.json # 24 checks - Crashes, logcat, temp artifacts
    ├── selinux.json       #  25 checks - Enforcement, policy, audit
    ├── storage.json       #  24 checks - Encryption, partitions, backup
    ├── pos_security.json  #  24 checks - PCI-DSS, kiosk, NFC relay, PAX CVE
    ├── boot_security.json #  22 checks - Verified boot, AVB, dm-verity
    ├── cis_benchmark.json #  20 checks - CIS Android Benchmark v1.6.0
    ├── cryptography.json  #  19 checks - Keystore, StrongBox, algorithms
    ├── malware.json       #  18 checks - Root, Frida, Xposed, RATs, scrapers
    ├── usb_security.json  #  16 checks - USB debug, MTP, gadget mode
    ├── device_management.json # 13 checks - MDM, accounts, dev options
    ├── input.json         #   9 checks - Keyboards, accessibility, IME
    ├── nfc_security.json  #   7 checks - NFC, reader mode, secure element
    └── adb_security.json  #   4 checks - ADB keys, network ADB
```

---

## Future Roadmap

- [ ] `--category` flag to run specific categories
- [ ] `--severity` flag to filter by level
- [ ] `--format json` for JSON output
- [ ] Exit codes for CI/CD integration
- [ ] CVE Correlation Engine
- [ ] Binary Hardening Analysis (ASLR, NX, PIE)
- [ ] HARDAX Risk Score (0-100)
- [ ] Save baseline configuration
- [ ] Diff reports between scans
- [ ] Device profiles (IoT/Automotive/Medical presets)
- [ ] CIS Android Benchmark full mapping
- [ ] OWASP MASVS/MSTG mapping
- [ ] NIST guidelines mapping
- [ ] Remediation suggestions
- [ ] Multi-device parallel scanning
- [ ] Web dashboard (Flask/FastAPI)
- [ ] Plugin architecture
- [ ] APK analysis integration
- [ ] Firmware extraction support
