# HARDAX - Hardening Audit eXaminer

```
  _    _          _____  _____      __   __
 | |  | |   /\   |  __ \|  __ \   /\ \ / /
 | |__| |  /  \  | |__) | |  | | /  \\ V / 
 |  __  | / /\ \ |  _  /| |  | |/ /\ \> <  
 | |  | |/ ____ \| | \ \| |__| / ____ / . \ 
 |_|  |_/_/    \_\_|  \_\_____/_/    \_/ \_\

    Hardening Audit eXaminer for Android & IoT
```

## 🛡️ Overview

**HARDAX** (Hardening Audit eXaminer) is a comprehensive security configuration auditing tool for Android and IoT devices. It systematically checks device configurations against security best practices and generates detailed reports highlighting potential vulnerabilities and misconfigurations.

### Key Features

- **257 Security Checks** across 52 categories
- **ADB & SSH Modes** for flexible connectivity
- **Beautiful CLI** with real-time progress and colored output
- **Modern HTML Reports** with collapsible sections and search
- **CSV & TXT Reports** for integration and archival
- **Dark/Light Theme** toggle in HTML reports
- **Category Statistics** showing risk breakdown per area

## 📋 Categories Covered

| Category | Checks | Category | Checks |
|----------|--------|----------|--------|
| Bluetooth Security | 29 | Network Security | 15 |
| Boot Security | 12 | ADB/Debug Settings | 8 |
| Privacy Settings | 18 | App Permissions | 14 |
| Encryption | 10 | Kernel Hardening | 12 |
| SELinux/Policy | 8 | Root Detection | 6 |
| And many more... | | | |

## 🚀 Quick Start

### Prerequisites

- Python 3.7+
- ADB (Android Debug Bridge) installed and in PATH
- USB Debugging enabled on target device

### Installation

```bash
# Clone or download HARDAX
git clone https://github.com/yourusername/hardax.git
cd hardax

# No additional dependencies for ADB mode
# For SSH mode: pip install paramiko
```

### Basic Usage

```bash
# Scan connected Android device (auto-detects)
python hardax.py --json-dir ./commands

# Scan specific device
python hardax.py --json-dir ./commands --serial DEVICE_SERIAL

# Scan via SSH (for IoT/embedded devices)
python hardax.py --mode ssh --host 192.168.1.100 --ssh-user root --ssh-pass password

# Show commands as they execute
python hardax.py --json-dir ./commands --show-commands
```

## 📊 Reports

HARDAX generates three types of reports in timestamped folders:

### HTML Report (Recommended)
- **Collapsible Categories**: Click to expand/collapse each security category
- **Search Functionality**: Filter checks by keyword
- **Category Statistics**: Quick overview of issues per category
- **Interactive Chart**: Visual breakdown of results
- **Dark/Light Theme**: Toggle for different viewing preferences

### CSV Report
- Machine-readable format
- Easy to import into Excel, databases, or other tools
- Contains all check details

### TXT Report
- Plain text format
- Ideal for archival and quick review
- Contains full audit trail

## 🎯 Use Cases

1. **Pre-Deployment Audits**: Verify device security before production
2. **Compliance Checks**: Ensure devices meet security baselines
3. **Penetration Testing**: Identify attack surface and misconfigurations
4. **Security Research**: Analyze Android/IoT security posture
5. **Incident Response**: Quickly assess compromised device configuration

## 📁 Directory Structure

```
HARDAX/
├── hardax.py           # Main scanner script
├── commands/           # Security check definitions
│   ├── bluetooth.json
│   ├── boot_security.json
│   ├── network.json
│   └── ... (38 JSON files)
├── README.md
└── hardax_output/      # Generated reports
    ├── html_report_YYYYMMDD_HHMMSS/
    │   ├── audit_report.html
    │   └── audit_report.csv
    └── txt_report_YYYYMMDD_HHMMSS/
        └── audit_report.txt
```

## 🔧 Adding Custom Checks

Create a JSON file in the `commands/` directory:

```json
[
  {
    "category": "CUSTOM_CATEGORY",
    "label": "Check Name",
    "command": "getprop ro.custom.setting",
    "safe_pattern": "expected_safe_value",
    "level": "critical",
    "description": "What this check verifies"
  }
]
```

### Check Levels
- `critical` / `high` → Red status when unsafe
- `warning` / `medium` → Yellow status when unsafe  
- `info` / `low` → Blue status (informational)

## 📖 Command Line Options

| Option | Description |
|--------|-------------|
| `--mode` | Connection mode: `adb` (default) or `ssh` |
| `--json` | Path to single JSON checks file |
| `--json-dir` | Directory containing JSON check files |
| `--serial` | ADB device serial number |
| `--host` | SSH hostname/IP |
| `--port` | SSH port (default: 22) |
| `--ssh-user` | SSH username |
| `--ssh-pass` | SSH password |
| `--out` | Output directory (default: `hardax_output`) |
| `--show-commands` | Display commands during execution |
| `--progress-numbers` | Show simple X/Y progress |

## 🤝 Contributing

Contributions welcome! Areas of interest:
- Additional security checks
- Support for more device types
- Report format improvements
- Bug fixes and optimizations

## 📜 License

MIT License - See LICENSE file for details.

## ⚠️ Disclaimer

HARDAX is intended for authorized security testing only. Always obtain proper authorization before scanning devices you do not own.

---

**HARDAX** - *Security is not optional, it's fundamental.*
