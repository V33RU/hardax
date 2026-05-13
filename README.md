<h1 align="center">HARDAX</h1>


<p align="center">
  <img src="https://img.shields.io/badge/version-5.2.1-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.11+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/checks-706-orange.svg" alt="Checks">
  <img src="https://img.shields.io/badge/categories-25-purple.svg" alt="Categories">
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

**HARDAX** (Hardening Audit eXaminer) is a comprehensive security configuration auditor for Android-based devices. It performs **686 security checks** across **25 categories** to identify misconfigurations, vulnerabilities, and security weaknesses.

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
| **686 Security Checks** | Comprehensive coverage across 25 security categories |
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

### Install with pip (recommended)

```bash
# Core (ADB mode only)
pip install hardax

# With SSH support (paramiko)
pip install 'hardax[ssh]'

# With UART / serial support (pyserial)
pip install 'hardax[uart]'

# With certificate audit support (cryptography)
pip install 'hardax[certs]'

# Everything
pip install 'hardax[all]'
```

After installation the `hardax` console command is available:

```bash
adb devices
hardax
```

### Install from source (development)

```bash
git clone https://github.com/V33RU/hardax.git
cd hardax
pip install -e '.[all]'

# Or run without installing
python3 -m hardax
```

---

## Usage

### Basic Usage (ADB)

```bash
# Auto-detect connected device
hardax

# Show commands being executed
hardax --show-commands

# Load all check files from commands/ directory
hardax --json-dir commands

# Specify device by serial
hardax --serial DEVICE_SERIAL

# Custom output directory
hardax --out ./my_reports

# Skip certificate audit
hardax --skip-certs
```

### SSH Mode (Network)

```bash
hardax --mode ssh --host 192.168.1.100 --ssh-user root --ssh-pass password
```

### UART Mode (Serial Console)

```bash
# Auto-detect baud rate
hardax --mode uart --uart-port /dev/ttyUSB0

# Specify baud rate
hardax --mode uart --uart-port /dev/ttyUSB0 --baud 115200

# Windows
hardax --mode uart --uart-port COM3 --baud 115200
```

### Network ADB

```bash
adb connect 192.168.1.100:5555
hardax --json-dir commands
```

### All Options

```
usage: hardax [OPTIONS]

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

HARDAX organizes **686 checks** into **25 security categories**:

| Category | Checks | Description |
|----------|--------|-------------|
| **SYSTEM** | 85 | Kernel, memory, TEE (QSEE/Mobicore/TEEGRIS/Trusty), SECCOMP, time, power, build properties, emulator detection, SIM status |
| **BLUETOOTH** | 83 | BLE/Classic, pairing, profiles (PAN, HFP, A2DP, HID, SPP, OPP, MAP), L2CAP, ATT, SMP, GAP, attack surfaces |
| **NETWORK** | 60 | Ports, WiFi, cellular, VPN, MQTT, CoAP, CAN bus, HL7, DICOM, active connections |
| **PRIVACY** | 47 | Biometrics, screen lock, location, sensors, clipboard, audio |
| **APPS** | 44 | Permissions, overlay attacks, installation sources, backup audit, dangerous perms |
| **BINARY_HARDENING** | 36 | PIE, NX, RELRO, stack canaries, stripped symbols, ASLR, kptr_restrict |
| **PARTITION** | 27 | dm-verity, OverlayFS, A/B slots, FBE/FDE, mount flags, block device permissions |
| **CERTIFICATE_AUDIT** | 25 | CA certificates, user certs, pinning bypass, keystore, expiry analysis |
| **SELINUX** | 25 | SELinux enforcement, policy, audit, context, boot flags |
| **POS_SECURITY** | 24 | PCI-DSS compliance, payment apps, kiosk mode, RAM scraper, NFC relay, PAX CVE |
| **STORAGE** | 24 | Filesystem, backup, encryption, partitions |
| **FORENSIC_INDICATORS** | 22 | Crash history, kernel panics, logcat anomalies, temp artifacts, clipboard forensics |
| **ATTESTATION** | 20 | SafetyNet/Play Integrity, Knox warranty bit, TIMA, RKP, Titan M, fs-verity, bypass detection |
| **AUTOMOTIVE** | 20 | Vehicle-specific checks, CAN bus, infotainment |
| **BOOT_SECURITY** | 20 | Verified boot, AVB, dm-verity, bootloader, integrity |
| **CRYPTOGRAPHY** | 18 | Encryption, keys, credentials, API keys, certificates |
| **MALWARE** | 18 | Root/Magisk/SuperSU, Frida, Xposed/LSPosed, RATs, keyloggers, memory scrapers, root cloaking |
| **CIS_BENCHMARK** | 17 | CIS Android Benchmark v1.6.0 controls (89% coverage) |
| **USB_SECURITY** | 16 | USB debugging, interfaces, serial ports, gadget mode |
| **CVE_INDICATORS** | 15 | Dirty Pipe, Bad Binder, Dirty COW, MTK-su, Exynos baseband, Mali GPU, kernel CVE ranges |
| **DEVICE_MANAGEMENT** | 13 | MDM, accounts, developer options |
| **INPUT** | 9 | Keyboards, accessibility, input methods |
| **MEDICAL** | 7 | Medical device-specific checks |
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
├── pyproject.toml         # Package metadata, dependencies, entry point
├── README.md              # This file
├── LICENSE                # MIT
└── hardax/                # The installable Python package
    ├── __init__.py        # Main engine (was hardax.py)
    ├── __main__.py        # Enables 'python -m hardax'
    ├── templates/
    │   └── report.html    # Interactive HTML report template
    └── commands/          # Security check definitions (706 checks, 25 categories)
        ├── system.json        #  85 checks - Kernel, TEE (QSEE/Mobicore/TEEGRIS/Trusty), SECCOMP, build, emulator
        ├── bluetooth.json     #  83 checks - BLE/Classic, pairing, all profiles
        ├── network.json       #  60 checks - Ports, WiFi, VPN, IoT protocols
        ├── privacy.json       #  47 checks - Biometrics, location, sensors
        ├── apps.json          #  44 checks - Permissions, overlay, backup, install
        ├── binary_hardening.json # 36 checks - PIE, NX, RELRO, stack canaries, ASLR
        ├── partition.json     #  27 checks - dm-verity, A/B slots, FBE, mount flags
        ├── certificate_audit.json # 25 checks - CA certs, expiry, MITM
        ├── selinux.json       #  25 checks - Enforcement, policy, audit
        ├── pos_security.json  #  24 checks - PCI-DSS, kiosk, NFC relay, PAX CVE
        ├── storage.json       #  24 checks - Encryption, partitions, backup
        ├── forensic_indicators.json # 22 checks - Crashes, logcat, temp artifacts
        ├── attestation.json   #  20 checks - SafetyNet/Play Integrity, Knox, Titan M, bypass detection
        ├── automotive.json    #  20 checks - Vehicle, CAN bus, infotainment
        ├── boot_security.json #  20 checks - Verified boot, AVB, dm-verity
        ├── cryptography.json  #  18 checks - Keystore, StrongBox, algorithms
        ├── malware.json       #  18 checks - Root, Frida, Xposed, RATs, scrapers
        ├── cis_benchmark.json #  17 checks - CIS Android Benchmark v1.6.0
        ├── usb_security.json  #  16 checks - USB debug, MTP, gadget mode
        ├── cve_indicators.json # 15 checks - Dirty Pipe, Bad Binder, MTK-su, kernel CVEs
        ├── device_management.json # 13 checks - MDM, accounts, dev options
        ├── input.json         #   9 checks - Keyboards, accessibility, IME
        ├── medical.json       #   7 checks - Medical device-specific
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
