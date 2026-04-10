<h1 align="center">HARDAX</h1>


<p align="center">
  <img src="https://img.shields.io/badge/version-4.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.11+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/checks-664-orange.svg" alt="Checks">
  <img src="https://img.shields.io/badge/categories-23-purple.svg" alt="Categories">
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

**HARDAX** (Hardening Audit eXaminer) is a comprehensive security configuration auditor for Android-based devices. It performs **664 security checks** across **23 categories** to identify misconfigurations, vulnerabilities, and security weaknesses.

HARDAX is designed for:
- **Security Researchers** - Penetration testing and vulnerability assessment
- **IoT Security Teams** - Auditing Android-based IoT devices
- **POS Security Auditors** - PCI-DSS compliance verification for payment terminals
- **Enterprise Security** - MDM compliance verification
- **Developers** - Pre-release security validation

---

## Features

| Feature | Description |
|---------|-------------|
| **664 Security Checks** | Comprehensive coverage across 23 security categories |
| **POS/Payment Terminal Support** | 24 PCI-DSS focused checks for payment devices |
| **Malware & Hooking Detection** | 18 checks for rootkits, RATs, Frida, Xposed, keyloggers, memory scrapers |
| **Certificate Audit** | CA certificate analysis with expiry/age calculation - 27 checks |
| **Root Auto-Detection** | Detects root method (Magisk/SuperSU/su/ssh-root/uart-root) and adapts privilege escalation accordingly |
| **ADB Resilience** | 5-layer protection: connection check, auto-reconnect, timeout, SKIPPED status |
| **Triple Connection Modes** | ADB (USB/Network), SSH, and UART serial console support |
| **UART Shell Support** | Connect over serial console with auto baud detection, user/root shell identification |
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

HARDAX works with any Android-based device accessible via ADB, SSH, or UART:

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
git clone https://github.com/v33ru/hardax.git
cd hardax

# Connect your device via USB
adb devices

# Run HARDAX
python3 hardax.py
```

### Optional Dependencies

```bash
# For Linux
pip install paramiko cryptography pyserial

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

### UART Mode (Serial Console)

```bash
# Auto-detect baud rate
python3 hardax.py --mode uart --uart-port /dev/ttyUSB0

# Specify baud rate
python3 hardax.py --mode uart --uart-port /dev/ttyUSB0 --baud 115200

# Windows
python3 hardax.py --mode uart --uart-port COM3 --baud 115200
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
  --mode {adb,ssh,uart} Connection mode (default: adb)
  --serial SERIAL       ADB device serial number
  --host HOST           SSH hostname/IP
  --port PORT           SSH port (default: 22)
  --ssh-user USER       SSH username
  --ssh-pass PASS       SSH password
  --uart-port PORT      UART serial port (e.g. /dev/ttyUSB0, COM3)
  --baud RATE           UART baud rate (0 = auto-detect, default: 0)
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

HARDAX organizes **664 checks** into **23 security categories**:

| Category | Checks | Description |
|----------|--------|-------------|
| **SYSTEM** | 83 | Kernel, memory, TEE, time, power, build properties, emulator detection, SIM status |
| **BLUETOOTH** | 84 | BLE/Classic, pairing, profiles (PAN, HFP, A2DP, HID, SPP, OPP, MAP), L2CAP, ATT, SMP, GAP, attack surfaces |
| **NETWORK** | 60 | Ports, WiFi, cellular, VPN, MQTT, CoAP, CAN bus, HL7, DICOM, active connections |
| **APPS** | 46 | Permissions, overlay attacks, installation sources, backup audit, dangerous perms |
| **PRIVACY** | 47 | Biometrics, screen lock, location, sensors, clipboard, audio |
| **BINARY_HARDENING** | 36 | PIE, NX, RELRO, stack canaries, stripped symbols, ASLR |
| **PARTITION** | 27 | dm-verity, OverlayFS, A/B slots, FBE/FDE, mount flags, block device permissions |
| **CERTIFICATE_AUDIT** | 27 | CA certificates, user certs, pinning bypass, keystore, expiry analysis |
| **SELINUX** | 25 | SELinux enforcement, policy, audit, context, boot flags |
| **STORAGE** | 24 | Filesystem, backup, encryption, partitions |
| **POS_SECURITY** | 24 | PCI-DSS compliance, payment apps, kiosk mode, RAM scraper, NFC relay, PAX CVE |
| **FORENSIC_INDICATORS** | 23 | Crash history, kernel panics, logcat anomalies, temp artifacts, clipboard forensics |
| **BOOT_SECURITY** | 22 | Verified boot, AVB, dm-verity, bootloader, integrity |
| **AUTOMOTIVE** | 21 | Vehicle-specific checks, CAN bus, infotainment |
| **CRYPTOGRAPHY** | 20 | Encryption, keys, credentials, API keys, certificates |
| **CIS_BENCHMARK** | 20 | CIS Android Benchmark v1.6.0 controls (89% coverage) |
| **MALWARE** | 18 | Root/Magisk/SuperSU, Frida, Xposed/LSPosed, RATs, keyloggers, memory scrapers, root cloaking |
| **USB_SECURITY** | 16 | USB debugging, interfaces, serial ports, gadget mode |
| **DEVICE_MANAGEMENT** | 14 | MDM, accounts, developer options |
| **INPUT** | 9 | Keyboards, accessibility, input methods |
| **NFC_SECURITY** | 7 | NFC state, Android Beam, tap-to-pay, reader mode, secure element (eSE/UICC) |
| **MEDICAL** | 7 | Medical device-specific checks |
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
| `level` | Yes | Severity: `info`, `warning`, `critical` |
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
├── hardax.py              # Main engine
├── requirements.txt       # Python dependencies (paramiko, cryptography, pyserial)
├── README.md              # This file
├── templates/             # Report templates
│   └── report.html        # Interactive HTML report template
├── tests/                 # Unit tests for check definitions
│   └── test_partition_checks.py
└── commands/              # Security check definitions (664 checks, 23 categories)
    ├── bluetooth.json     #  84 checks - BLE/Classic, pairing, all profiles
    ├── system.json        #  83 checks - Kernel, TEE, build, emulator, memory
    ├── network.json       #  60 checks - Ports, WiFi, VPN, IoT protocols
    ├── privacy.json       #  47 checks - Biometrics, location, sensors
    ├── apps.json          #  46 checks - Permissions, overlay, backup, install
    ├── binary_hardening.json # 36 checks - PIE, NX, RELRO, stack canaries, ASLR
    ├── partition.json     #  27 checks - dm-verity, A/B slots, FBE, mount flags
    ├── certificate_audit.json # 27 checks - CA certs, expiry, MITM
    ├── selinux.json       #  25 checks - Enforcement, policy, audit
    ├── storage.json       #  24 checks - Encryption, partitions, backup
    ├── pos_security.json  #  24 checks - PCI-DSS, kiosk, NFC relay, PAX CVE
    ├── forensic_indicators.json # 23 checks - Crashes, logcat, temp artifacts
    ├── boot_security.json #  22 checks - Verified boot, AVB, dm-verity
    ├── automotive.json    #  21 checks - Vehicle, CAN bus, infotainment
    ├── cryptography.json  #  20 checks - Keystore, StrongBox, algorithms
    ├── cis_benchmark.json #  20 checks - CIS Android Benchmark v1.6.0
    ├── malware.json       #  18 checks - Root, Frida, Xposed, RATs, scrapers
    ├── usb_security.json  #  16 checks - USB debug, MTP, gadget mode
    ├── device_management.json # 14 checks - MDM, accounts, dev options
    ├── input.json         #   9 checks - Keyboards, accessibility, IME
    ├── nfc_security.json  #   7 checks - NFC, reader mode, secure element
    ├── medical.json       #   7 checks - Medical device-specific
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
