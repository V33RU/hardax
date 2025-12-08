# CRISCAN - Critical Infrastructure Security Scanner

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/python-3.8+-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/platform-Linux-blue.svg" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-green.svg" alt="License">
</p>

<p align="center">
  <b>Android Security Audit Framework for Critical Infrastructure</b><br>
  <i>Medical Devices | Connected Vehicles | Industrial IoT | Smart Infrastructure</i>
</p>

---

## 🎯 Overview

**CRISCAN** (Critical Infrastructure Security Scanner) is a Python-based security audit framework designed for Android-based critical systems. It performs comprehensive security assessments using ADB and generates detailed reports in multiple formats.

### Target Systems

| Domain | Examples | Standards |
|--------|----------|-----------|
| 🏥 **Medical Devices** | Patient monitors, infusion pumps, diagnostic equipment | FDA 524B, HIPAA |
| 🚗 **Connected Vehicles** | Android Automotive, IVI, telematics units | ISO 21434, UNECE R155/R156 |
| 🏭 **Industrial IoT** | SCADA HMIs, PLCs, industrial gateways | IEC 62443, NIST 800-82 |
| 📡 **Smart Infrastructure** | Smart grid, building automation | OWASP IoT, NIST 8259A |

---

## ✨ Features

- ✅ **40+ Security Check Categories** - Boot security, encryption, network, apps, and more
- ✅ **Industry Profiles** - Pre-configured audits for medical, automotive, industrial
- ✅ **Compliance Mapping** - OWASP IoT, NIST, ISO 21434, FDA 524B, IEC 62443
- ✅ **Multi-Format Reports** - HTML (interactive), TXT, CSV, JSON
- ✅ **CI/CD Integration** - Exit codes based on findings for pipeline automation
- ✅ **CVE References** - Links to known vulnerabilities
- ✅ **Auto Device Detection** - Works with USB and network-connected devices

---

## 📦 Installation

### Requirements

- Python 3.8+
- ADB (Android Debug Bridge)
- Linux (recommended) or macOS

### Quick Install

```bash
# Clone the repository
git clone https://github.com/IoTSRG/criscan.git
cd criscan

# Install ADB (Ubuntu/Debian)
sudo apt install android-tools-adb

# Make executable
chmod +x criscan.py
```

---

## 🚀 Usage

### Basic Usage

```bash
# Run full audit with all checks
python3 criscan.py --json-dir commands/

# Target specific device
python3 criscan.py --serial DEVICE123 --json-dir commands/

# Run specific check files only
python3 criscan.py --json commands/boot_security.json --json commands/network.json
```

### Industry Profiles

```bash
# Medical Device Audit (FDA 524B / HIPAA)
python3 criscan.py --profile medical --json-dir commands/

# Automotive Audit (ISO 21434 / UNECE R155)
python3 criscan.py --profile automotive --json-dir commands/

# Industrial IoT Audit (IEC 62443)
python3 criscan.py --profile industrial --json-dir commands/

# Full Comprehensive Audit
python3 criscan.py --profile full --json-dir commands/
```

### CI/CD Integration

```bash
# Fail if any critical issues found
python3 criscan.py --json-dir commands/ --ci --critical-threshold 0

# Fail if more than 5 warnings
python3 criscan.py --json-dir commands/ --ci --warning-threshold 5

# Exit codes:
#   0 = PASSED
#   1 = WARNINGS exceeded threshold
#   2 = CRITICAL issues exceeded threshold
```

### Output Formats

```bash
# Generate specific formats only
python3 criscan.py --json-dir commands/ --format html json

# All formats (default)
python3 criscan.py --json-dir commands/ --format html txt csv json
```

---

## 📁 Project Structure

```
criscan/
├── criscan.py              # Main scanner script
├── README.md               # This file
├── LICENSE                 # MIT License
│
└── commands/               # Security check definitions (JSON)
    ├── adb_security.json
    ├── adb_trust.json
    ├── additional_security.json
    ├── app_system_integrity.json
    ├── apps.json
    ├── apps_runtime.json
    ├── automotive.json         # 🚗 Automotive-specific checks
    ├── avb.json
    ├── bluetooth.json
    ├── boot_security.json
    ├── bootloader.json
    ├── bootloader_policy.json
    ├── checks_cis.json
    ├── debugging.json
    ├── dm_verity.json
    ├── filesystem.json
    ├── frida.json
    ├── industrial_iot.json     # 🏭 Industrial-specific checks
    ├── input_security.json
    ├── integrity.json
    ├── kernel.json
    ├── logs.json
    ├── malware_scan.json
    ├── medical_device.json     # 🏥 Medical-specific checks
    ├── memory.json
    ├── network.json
    ├── network_ipv4.json
    ├── network_ipv6.json
    ├── patching.json
    ├── path_abuse.json
    ├── policy.json
    ├── process_snapshot.json
    ├── root.json
    ├── root_trace.json
    ├── selinux.json
    ├── slots_recovery.json
    ├── storage.json
    ├── system.json
    ├── tee_tpm.json
    └── user_privacy.json
```

---

## 📋 JSON Check Format

Each check follows this structure:

```json
{
  "category": "BOOT SECURITY",
  "label": "Verified Boot State",
  "command": "getprop ro.boot.verifiedbootstate",
  "safe_pattern": "^green$",
  "level": "critical",
  "description": "Verified boot must be green for locked bootloader",
  "compliance": {
    "owasp_iot": ["OWASP-IoT-4"],
    "iso_21434": ["RQ-08-01"],
    "fda_524b": ["Software Integrity"]
  },
  "cve_related": ["CVE-2017-13156"]
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `category` | Yes | Group name for the check |
| `label` | Yes | Short descriptive title |
| `command` | Yes | ADB shell command to execute |
| `safe_pattern` | Yes | Regex pattern - match = SAFE |
| `level` | Yes | `critical`, `warning`, or `info` |
| `description` | No | Detailed explanation |
| `compliance` | No | Mapping to standards |
| `cve_related` | No | Related CVE identifiers |

---

## 📊 Report Outputs

Reports are saved to `criscan_reports/audit_YYYYMMDD_HHMMSS/`:

| Format | File | Description |
|--------|------|-------------|
| **HTML** | `audit_report.html` | Interactive report with search, filters, charts |
| **TXT** | `audit_report.txt` | Plain text for terminals/logs |
| **CSV** | `audit_report.csv` | Spreadsheet import, SIEM integration |
| **JSON** | `audit_report.json` | Machine-readable, API integration |

---

## 🔐 Supported Compliance Frameworks

| Framework | Domain | Checks |
|-----------|--------|--------|
| **OWASP IoT Top 10** | All IoT | Weak passwords, insecure network, update mechanisms |
| **NISTIR 8259A** | Federal/Commercial | Core baseline capabilities |
| **ISO/SAE 21434** | Automotive | Cybersecurity risk management |
| **UNECE WP.29 R155** | Automotive (54 countries) | CSMS requirements |
| **UNECE WP.29 R156** | Automotive | Software update management |
| **FDA Section 524B** | Medical Devices | Premarket cybersecurity |
| **HIPAA Security Rule** | Healthcare | PHI protection |
| **IEC 62443** | Industrial | IACS security |
| **CIS Android Benchmark** | Enterprise | Hardening guidelines |

---

## 🛠️ Troubleshooting

### No devices detected

```bash
# Restart ADB server
adb kill-server && adb start-server

# Check device connection
adb devices -l

# For network devices
adb connect <ip>:5555
```

### Multiple devices

```bash
# Specify device serial
python3 criscan.py --serial <SERIAL> --json-dir commands/
```

### Permission denied

```bash
# On device: Accept RSA fingerprint prompt
# On device: Enable USB debugging in Developer Options
```

---

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add your checks to `commands/` as JSON files
4. Submit a pull request

### Adding New Checks

Create a new JSON file in `commands/` following the format above, or add checks to existing category files.

---

## 📄 License

MIT License - see [LICENSE](LICENSE) file.

---

## 🙏 Acknowledgments

- Original ANDI (Android Inspector) project
- OWASP IoT Security Project
- NIST Cybersecurity for IoT Program
- ISO/SAE 21434 Working Group



<p align="center">
  Made with ❤️ by <b>IoTSRG Team</b><br>
  <i>Securing the Connected World</i>
</p>
