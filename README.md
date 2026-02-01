# CRISCAN - Critical Infrastructure Security Scanner

## Overview

A comprehensive Android/Linux security audit framework with **257 unique security checks** across **52 categories**.

| Metric | Value |
|--------|-------|
| **Total Checks** | 257 |
| **Categories** | 52 |
| **Critical Checks** | 62 |
| **Warning Checks** | 81 |

## Security Categories

| Category | Checks | What It Tests |
|----------|--------|---------------|
| Bluetooth | 29 | BLE/BR-EDR security, SSP, KNOB, BlueBorne |
| User Privacy | 12 | Location, contacts, camera, microphone |
| System | 11 | ASLR, KASLR, NX, SECCOMP |
| Boot Security | 9 | Verified boot, dm-verity, encryption |
| Hardware Info | 9 | Baseband, vendor patch, Treble, GKI |
| Cryptography | 7 | Keystore, StrongBox, encryption |
| Biometrics | 7 | Fingerprint, Face unlock, Smart Lock |
| Developer Options | 7 | Mock location, OEM unlock |
| MDM & Enterprise | 7 | Device admin, work profile |
| Screen Security | 8 | Lock type, notifications, overlays |
| WiFi Extended | 8 | WiFi Direct, hotspot, MAC randomization |
| Dangerous Permissions | 8 | SMS, accessibility, notification access |
| USB Security | 5 | ADB, MTP, OTG |
| NFC Security | 5 | NFC, Android Beam, HCE |
| Certificates | 5 | User CA certs, SSL pinning bypass |
| Voice Assistant | 5 | Voice unlock, always-on listening |
| SIM Security | 6 | SIM PIN, carrier lock |
| SELinux | 5 | Enforcing mode, policy, denials |
| ... and 34 more categories | |

## Usage

```bash
# Basic scan
python3 criscan.py --json-dir commands

# With device serial
python3 criscan.py --serial DEVICE123 --json-dir commands

# SSH mode (Linux devices)
python3 criscan.py --mode ssh --host 192.168.1.100 \
    --ssh-user admin --ssh-pass password --json-dir commands

# Show live command execution
python3 criscan.py --json-dir commands --show-commands
```

## Output

Reports generated in `android_audit_output/`:
- `html_report_TIMESTAMP/audit_report.html` - Interactive HTML with charts
- `html_report_TIMESTAMP/audit_report.csv` - CSV for analysis
- `txt_report_TIMESTAMP/audit_report.txt` - Plain text log

## Requirements

- Python 3.6+
- ADB (for Android devices) or SSH access (for Linux)
- USB debugging enabled on target device

## Files

```
CRISCAN/
├── criscan.py               # Main scanner
├── commands/                # 52 JSON files, 257 unique checks
│   ├── bluetooth.json       # 29 BLE/BR-EDR security checks
│   ├── cryptography.json    # Encryption & keystore
│   ├── dangerous_permissions.json
│   ├── usb_security.json
│   └── ... (48 more)
└── README.md                # This file
```

## Check Distribution by Severity

| Severity | Count | Description |
|----------|-------|-------------|
| Critical | 62 | Immediate security risk |
| High | 9 | Significant vulnerability |
| Warning | 81 | Security concern |
| Info | 97 | Informational |

## License

Security Research Tool - Use Responsibly
