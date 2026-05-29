<h1 align="center">HARDAX</h1>


<p align="center">
  <a href="https://pypi.org/project/hardax/">
    <img src="https://img.shields.io/pypi/v/hardax.svg?label=pypi&color=blue" alt="PyPI">
  </a>
  <a href="https://pypi.org/project/hardax/">
    <img src="https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg" alt="Python 3.10 | 3.11 | 3.12">
  </a>
  <img src="https://img.shields.io/badge/checks-750-orange.svg" alt="Checks">
  <img src="https://img.shields.io/badge/categories-26-purple.svg" alt="Categories">
  <a href="https://github.com/V33RU/hardax/blob/main/LICENSE">
    <img src="https://img.shields.io/badge/license-MIT-red.svg" alt="License">
  </a>
  <a href="https://github.com/V33RU/hardax/actions/workflows/ci.yml">
    <img src="https://github.com/V33RU/hardax/actions/workflows/ci.yml/badge.svg" alt="CI">
  </a>
  <a href="https://github.com/V33RU/hardax/wiki">
    <img src="https://img.shields.io/badge/wiki-documentation-lightgrey.svg" alt="Wiki">
  </a>
</p>

<p align="center">
  <a href="https://pypi.org/project/hardax/"><strong>pip install hardax</strong></a>
</p>

<p align="center">
</p>

![HARDAX overview: Android security configuration auditor](https://raw.githubusercontent.com/V33RU/hardax/main/.github/assets/hardax-overview.png)

---

## Overview

**HARDAX** (Hardening Audit eXaminer) is a comprehensive security configuration auditor for Android-based devices. It performs **750 security checks** across **26 categories** to identify misconfigurations, vulnerabilities, and security weaknesses.

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
| **750 Security Checks** | Comprehensive coverage across 26 security categories |
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

- Python 3.10 or higher
- ADB (Android Debug Bridge) installed and in PATH
- USB Debugging enabled on target device

### Install with pip (recommended)

```bash
pip install hardax
```

paramiko, pyserial, and cryptography are pulled in automatically so all four modes (ADB, SSH, UART, certificate audit) work out of the box.

The `[ssh]`, `[uart]`, `[certs]`, `[all]` extras still exist for backward compat with any script that used them; they are now no-ops since the deps are required.

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

The target host's SSH key must be in `~/.ssh/known_hosts` first, otherwise the connection is refused (strict host-key checking, the safe default). Populate it once with:

```bash
ssh-keyscan -H -t ed25519,rsa 192.168.1.100 >> ~/.ssh/known_hosts
```

For CI / lab environments auditing many fresh devices where pre-population is impractical, pass `--ssh-tofu` to silently accept unknown host keys on first contact. A clear warning is printed each time:

```bash
hardax --mode ssh --host 192.168.1.100 --ssh-user root --ssh-pass "$AUDIT_PASS" --ssh-tofu
```

The SSH password can also come from the `HARDAX_SSH_PASS` environment variable, which keeps it out of `ps` and shell history.

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
  --ssh-pass PASS       SSH password (also accepts HARDAX_SSH_PASS env var)
  --ssh-tofu            SSH trust-on-first-use: silently accept unknown
                        host keys (CI / lab convenience; weakens MITM
                        protection on first connection). Default off.
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

HARDAX organizes **750 checks** into **26 security categories**:

| Category | Checks | Description |
|----------|--------|-------------|
| **SYSTEM** | 87 | Kernel, memory, TEE (QSEE/Mobicore/TEEGRIS/Trusty), SECCOMP, time, power, build properties, emulator detection, SIM status, device provisioning, WebView |
| **BLUETOOTH** | 83 | BLE/Classic, pairing, profiles (PAN, HFP, A2DP, HID, SPP, OPP, MAP), L2CAP, ATT, SMP, GAP, attack surfaces |
| **NETWORK** | 62 | Ports, WiFi, cellular (incl. Allow 2G), VPN, MQTT, CoAP, CAN bus, HL7, DICOM, hotspot WPA mode, active connections |
| **PRIVACY** | 48 | Biometrics, screen lock, location, sensors, clipboard, audio, Android 13+ Restricted Settings |
| **APPS** | 47 | Permissions, overlay attacks, install sources, backup audit, APK signature scheme, QUERY_ALL_PACKAGES, REQUEST_INSTALL_PACKAGES |
| **BINARY_HARDENING** | 36 | PIE, NX, RELRO, stack canaries, stripped symbols, ASLR, kptr_restrict |
| **PARTITION** | 35 | dm-verity, OverlayFS, A/B slots, FBE/FDE, mount flags (noexec / nosuid / nodev on /data, /storage/emulated, /mnt/media_rw, /cache, /metadata), block device permissions |
| **SELINUX** | 31 | SELinux enforcement, policy version, audit, context, boot flags |
| **CERTIFICATE_AUDIT** | 25 | CA certificates, user certs, pinning bypass, keystore, expiry analysis |
| **POS_SECURITY** | 24 | PCI-DSS compliance, payment apps, kiosk mode, RAM scraper, NFC relay, PAX CVE |
| **STORAGE** | 24 | Filesystem, backup, encryption, partitions |
| **FORENSIC_INDICATORS** | 22 | Crash history, kernel panics, logcat anomalies, temp artifacts, clipboard forensics |
| **ATTESTATION** | 20 | SafetyNet/Play Integrity, Knox warranty bit, TIMA, RKP, Titan M, fs-verity, bypass detection |
| **AUTOMOTIVE** | 20 | Vehicle-specific checks, CAN bus, infotainment |
| **BOOT_SECURITY** | 20 | Verified boot, AVB, dm-verity, bootloader, integrity |
| **CRYPTOGRAPHY** | 20 | Encryption, keys, credentials, API keys, certificates, kernel entropy, Widevine DRM level |
| **MALWARE** | 18 | Root/Magisk/SuperSU, Frida, Xposed/LSPosed, RATs, keyloggers, memory scrapers, root cloaking |
| **CIS_BENCHMARK** | 17 | CIS Android Benchmark v1.6.0 controls (89% coverage) |
| **USB_SECURITY** | 16 | USB debugging, interfaces, serial ports, gadget mode |
| **CVE_INDICATORS** | 33 | Dirty Pipe, Bad Binder, Dirty COW, MTK-su, Exynos baseband, Mali GPU, kernel CVE ranges, WebView debugging |
| **DEVICE_MANAGEMENT** | 13 | MDM, accounts, developer options |
| **INPUT** | 12 | Keyboards, accessibility, input methods, IME INTERNET audit, kbd layout, clipboard auto-clear |
| **MEDICAL** | 12 | Medical device-specific checks, IEEE 11073 PHD pairing, DICOM MWL, PACS C-STORE, insulin/cardiac telemetry |
| **NFC_SECURITY** | 9 | NFC state, Android Beam, tap-to-pay, reader mode, secure element (eSE/UICC), tag write protection, HCE AID priority |
| **ADB_SECURITY** | 8 | ADB keys, network ADB allowlist, debugging, shell privilege, USB-debug notify, adbd integrity hash |
| **MODERN_ANDROID** | 8 | Android 13/14/15 surface: Photo Picker, READ_MEDIA_*, POST_NOTIFICATIONS, FGS type, Theft Detection Lock, Identity Check, Restricted Networking, Advanced Protection |

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
    └── commands/          # Security check definitions (750 checks, 26 categories)
        ├── system.json        #  87 checks - Kernel, TEE (QSEE/Mobicore/TEEGRIS/Trusty), SECCOMP, build, emulator, WebView
        ├── bluetooth.json     #  83 checks - BLE/Classic, pairing, all profiles
        ├── network.json       #  62 checks - Ports, WiFi, VPN, IoT protocols, Allow 2G, hotspot WPA
        ├── privacy.json       #  48 checks - Biometrics, location, sensors, Restricted Settings
        ├── apps.json          #  47 checks - Permissions, overlay, backup, install, APK signature scheme
        ├── binary_hardening.json # 36 checks - PIE, NX, RELRO, stack canaries, ASLR
        ├── partition.json     #  35 checks - dm-verity, A/B slots, FBE, mount flags (noexec/nosuid/nodev)
        ├── selinux.json       #  31 checks - Enforcement, policy version, audit
        ├── certificate_audit.json # 25 checks - CA certs, expiry, MITM
        ├── pos_security.json  #  24 checks - PCI-DSS, kiosk, NFC relay, PAX CVE
        ├── storage.json       #  24 checks - Encryption, partitions, backup
        ├── forensic_indicators.json # 22 checks - Crashes, logcat, temp artifacts
        ├── attestation.json   #  20 checks - SafetyNet/Play Integrity, Knox, Titan M, bypass detection
        ├── automotive.json    #  20 checks - Vehicle, CAN bus, infotainment
        ├── boot_security.json #  20 checks - Verified boot, AVB, dm-verity
        ├── cryptography.json  #  20 checks - Keystore, StrongBox, kernel entropy, Widevine DRM
        ├── malware.json       #  18 checks - Root, Frida, Xposed, RATs, scrapers
        ├── cis_benchmark.json #  17 checks - CIS Android Benchmark v1.6.0
        ├── usb_security.json  #  16 checks - USB debug, MTP, gadget mode
        ├── cve_indicators.json # 33 checks - Dirty Pipe, Bad Binder, MTK-su, kernel CVEs, WebView debug
        ├── device_management.json # 13 checks - MDM, accounts, dev options
        ├── input.json         #   9 checks - Keyboards, accessibility, IME
        ├── medical.json       #   7 checks - Medical device-specific
        ├── nfc_security.json  #   7 checks - NFC, reader mode, secure element
        └── adb_security.json  #   4 checks - ADB keys, network ADB
```

---

## Roadmap

### Shipped

- [x] `--category` flag to run specific categories (v5.0.0)
- [x] `--severity` flag to filter by level (v5.0.0)
- [x] `--json-out` for machine-readable JSON output (v5.0.0)
- [x] `--exit-code` for CI/CD integration, exit 0/1/2 (v5.0.0)
- [x] Branch-protected `main` with PR workflow (v5.0.0)
- [x] CI workflow validates every `commands/*.json` regex (v5.0.0)
- [x] 20 new checks: mount-flag hardening, Restricted Settings, Allow 2G, Hotspot WPA, kernel entropy, Widevine DRM level, SELinux policy version, APK signature scheme, app permission audits, WebView SafeBrowsing and debug (v5.1.0)
- [x] Lock Screen Timeout false-positive fix (v5.1.0)
- [x] Pip-installable Python package, `pip install hardax` (v5.2.0)
- [x] PyPI Trusted Publishing on every GitHub release (v5.2.1)
- [x] 5 new SELinux checks from the 8ksec internals audit (v5.3.0)
- [x] Supply-chain hardening: SHA-pinned actions + Sigstore attestations on every wheel (v5.3.1)
- [x] Python 3.10 support (v5.3.3)
- [x] Safe SSH host-key default restored, `--ssh-tofu` opt-in for CI / lab convenience (v5.3.3)

### Open

Grouped by theme. Order within a group is rough priority.

#### Analysis features
- [ ] Baseline capture and diff (compare two scans, surface regressions)
- [ ] HARDAX Risk Score (0-100 composite across all 26 categories)
- [ ] CVE correlation (map findings to relevant CVE IDs automatically)

#### Additional security checks
- [ ] TLS protocol minimum / cipher policy on the device
- [ ] Wi-Fi Protected Management Frames (PMF) state
- [ ] TrustZone / TEE OS specific version (beyond presence detection)
- [ ] Hidden SSID hotspot detection
- [ ] Samsung Knox Container / Workspace state

#### Compliance mappings
- [ ] CIS Android Benchmark v1.6.0: fill the remaining 11% to 100% coverage
- [ ] OWASP MASVS / MSTG mapping per check
- [ ] NIST 800-53 / 800-171 mapping per check
- [ ] PCI-DSS 4.0 detailed mapping (POS terminals)

#### Tooling and ergonomics
- [ ] `--profile` flag with built-in presets (kiosk / POS / automotive / medical / IoT)
- [ ] Inline remediation suggestions in the HTML report
- [ ] Multi-device parallel scanning
- [ ] Plugin architecture for custom check loaders
- [ ] Official Docker image with adb / paramiko / pyserial pre-installed
- [ ] Web dashboard (Flask / FastAPI) for centralised audit storage and history

#### Code quality
- [ ] pytest suite covering the engine, transports, and reporters
- [ ] Split the 2400-line `hardax/__init__.py` into modules (transports, engine, reporters, cli)
- [ ] Formal JSON schema for `commands/*.json` (jsonschema validation)
- [ ] Type hints throughout, clean under `mypy --strict`

#### External integration
- [ ] APK static analysis (apktool / jadx integration)
- [ ] SARIF output (for GitHub code scanning and similar tools)
