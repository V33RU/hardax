<h1 align="center">HARDAX</h1>


<p align="center">
  <a href="https://pypi.org/project/hardax/">
    <img src="https://img.shields.io/pypi/v/hardax.svg?label=pypi&color=blue" alt="PyPI">
  </a>
  <a href="https://pypi.org/project/hardax/">
    <img src="https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12-blue.svg" alt="Python 3.10 | 3.11 | 3.12">
  </a>
  <img src="https://img.shields.io/badge/checks-777-orange.svg" alt="Checks">
  <img src="https://img.shields.io/badge/categories-28-purple.svg" alt="Categories">
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

**HARDAX** (Hardening Audit eXaminer) is a comprehensive security configuration auditor for Android-based devices. It performs **777 security checks** across **28 categories** to identify misconfigurations, vulnerabilities, and security weaknesses.

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
| **777 Security Checks** | Comprehensive coverage across 28 security categories |
| **Deterministic Analysis Engine** | Offline risk score (0-100), attack-chain correlation, prioritised remediation - reasons only over confirmed findings, no LLM, no network, no hallucination |
| **Optional AI Narrative** | Opt-in `--ai` LLM summary on top of the deterministic engine (local Ollama, or Anthropic/OpenAI with your own key). Sends only the redacted analysis summary, never raw device output. Off by default |
| **POS/Payment Terminal Support** | 24 PCI-DSS focused checks for payment devices |
| **Malware & Hooking Detection** | 18 checks for rootkits, RATs, Frida, Xposed, keyloggers, memory scrapers |
| **Certificate Audit** | CA certificate analysis with expiry/age calculation - 25 checks |
| **Root Auto-Detection** | Detects root method (Magisk/SuperSU/su/ssh-root/uart-root) and adapts privilege escalation accordingly |
| **ADB Resilience** | 5-layer protection: connection check, auto-reconnect, timeout, SKIPPED status |
| **Triple Connection Modes** | ADB (USB/Network), SSH, and UART serial console support |
| **UART Shell Support** | Connect over serial console with auto baud detection, user/root shell identification |
| **SSH Root Awareness** | Detects when SSH session is already root - skips unnecessary `su` probing |
| **6 Status Levels** | SAFE, WARNING, CRITICAL, VERIFY, INFO, SKIPPED |
| **5 Report Formats** | TXT, CSV, a detailed XLSX workbook, an interactive HTML dashboard, and machine-readable JSON |
| **Smart False Positive Prevention** | Catches empty output, service unavailability, and transport errors - marks as SKIPPED not CRITICAL |
| **Extensible JSON Checks** | Easy to add custom security checks - drop JSON, run |
| **Baseline Tamper Detection** | `--save-baseline` captures integrity values (VBMeta digest/size, adbd SHA-256); `--baseline` compares later audits and flags any change CRITICAL |
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

# Analysis is on by default. Weight prioritisation for a device profile:
hardax --profile pos        # or: medical, kiosk, automotive, iot, generic

# Disable the analysis layer entirely
hardax --no-analyze
```

### Analysis Engine

After the checks run, HARDAX adds a deterministic analysis layer that reasons
**only over the findings it already confirmed** - it runs no extra commands,
makes no network calls, and never invents a finding. It produces:

- a **risk score (0-100)** and letter grade,
- **attack chains** correlated from confirmed findings (a chain only appears
  when every supporting finding is actually present),
- a **prioritised "fix in this order"** list (chain members and
  profile-relevant categories are weighted up),
- a **VERIFY triage** grouping the manual-review items.

It is fully offline and deterministic (no LLM), so it is safe to run against
POS, medical, and other sensitive devices. The output appears in the terminal
summary, the HTML report, the TXT report, and under the `analysis` key of the
JSON report (`--json-out`).

### Optional AI Narrative (`--ai`)

On top of the deterministic engine you can add an **opt-in** LLM narrative that
explains the findings in plain language. It is off by default and never
replaces the deterministic analysis - it only re-phrases and connects the
findings the engine already confirmed, and is instructed never to introduce a
vulnerability that was not in the data.

```bash
# Local, fully offline (recommended for sensitive devices) - needs Ollama running
hardax --ai --ai-provider ollama --ai-model llama3

# Anthropic (key from ANTHROPIC_API_KEY env var, or --ai-key)
hardax --ai --ai-provider anthropic

# OpenAI
hardax --ai --ai-provider openai --ai-model gpt-4o-mini
```

Privacy model:

- Only the **redacted structured analysis** is sent (risk score, finding
  labels, categories, statuses, remediation text). The **raw output of each
  check is never sent** - so serials, PHI strings, IPs and ports do not leave
  the machine. A redaction backstop also scrubs IP/MAC/hex tokens.
- **Ollama runs locally** and sends nothing off-machine.
- Cloud providers (Anthropic/OpenAI) print a one-time data-egress warning and
  require consent (interactive, or `--ai-yes` for CI).
- API keys are read from env vars or `--ai-key` and are never stored, logged,
  or written to the report.
- If the model is unavailable or errors, the audit still completes on the
  deterministic engine alone.

The narrative appears as a clearly-labelled, visually distinct block in the
CLI, HTML and TXT reports, and under `analysis.ai_narrative` in JSON. It is not
a HARDAX finding and is marked as such.

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

### Baseline / Tamper Detection

Integrity values such as the AVB **VBMeta digest**, **VBMeta size**, and the
**adbd SHA-256** are device- and build-specific, so there is no universal
"safe" value to hard-code. Instead, capture a known-good baseline on a trusted
device and compare future audits against it. Any check carrying a
`baseline_key` participates automatically.

```bash
# 1. Capture a known-good baseline on a trusted, freshly-flashed device
hardax --save-baseline baseline.json

# 2. On later audits, compare against it. A changed value is reported CRITICAL (tamper)
hardax --baseline baseline.json

# Gate CI on tampering (exit 2 when any baseline value changed)
hardax --baseline baseline.json --exit-code
```

The baseline file records the device fingerprint, so HARDAX warns if you compare
against a baseline captured on a different build (where the values legitimately
differ). Connection/transport errors mark a check SKIPPED, and a key absent from
the baseline is reported VERIFY (nothing to compare). But a value that the
baseline recorded yet the device fails to return on the same build is treated as
a CRITICAL tamper/evasion indicator (fail closed), so an attacker cannot silence
the check by making it return nothing.

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
  --save-baseline FILE  Capture a known-good baseline of integrity values
                        (checks with a baseline_key) for later comparison
  --baseline FILE       Compare integrity values against a saved baseline;
                        a changed value is reported CRITICAL (tamper)

Hidden debug flags (prefix before other args):
  --net-debug           Verbose network check output
  --net-strict          Strict network check mode
  --cert-debug          Verbose certificate audit output
  --cert-limit N        Limit certificate files scanned (default: 50)
```

---

## Security Categories

HARDAX organizes **777 checks** into **28 security categories**:

| Category | Checks | Description |
|----------|--------|-------------|
| **SYSTEM** | 86 | Kernel, memory, TEE (QSEE/Mobicore/TEEGRIS/Trusty), SECCOMP, time, power, build properties, emulator detection, SIM status, device provisioning, WebView |
| **BLUETOOTH** | 82 | BLE/Classic, pairing, profiles (PAN, HFP, A2DP, HID, SPP, OPP, MAP), L2CAP, ATT, SMP, GAP, attack surfaces |
| **NETWORK** | 61 | Ports, WiFi, cellular (incl. Allow 2G), VPN, MQTT, CoAP, CAN bus, HL7, DICOM, hotspot WPA mode, active connections |
| **PRIVACY** | 42 | Screen lock, location, sensors, clipboard, audio, Android 13+ Restricted Settings |
| **APPS** | 47 | Permissions, overlay attacks, install sources, backup audit, APK signature scheme, QUERY_ALL_PACKAGES, REQUEST_INSTALL_PACKAGES |
| **BINARY_HARDENING** | 36 | PIE, NX, RELRO, stack canaries, stripped symbols, ASLR, kptr_restrict |
| **PARTITION** | 35 | dm-verity, OverlayFS, A/B slots, FBE/FDE, mount flags (noexec / nosuid / nodev on /data, /storage/emulated, /mnt/media_rw, /cache, /metadata), block device permissions |
| **SELINUX** | 30 | SELinux enforcement, policy version, audit, context, boot flags |
| **CERTIFICATE_AUDIT** | 25 | CA certificates, user certs, pinning bypass, keystore, expiry analysis |
| **POS_SECURITY** | 24 | PCI-DSS compliance, payment apps, kiosk mode, RAM scraper, NFC relay, PAX CVE |
| **STORAGE** | 24 | Filesystem, backup, encryption, partitions |
| **FORENSIC_INDICATORS** | 22 | Crash history, kernel panics, logcat anomalies, temp artifacts, clipboard forensics |
| **ATTESTATION** | 20 | SafetyNet/Play Integrity, Knox warranty bit, TIMA, RKP, Titan M, fs-verity, bypass detection |
| **AUTOMOTIVE** | 20 | Vehicle-specific checks, CAN bus, infotainment |
| **BOOT_SECURITY** | 27 | Verified boot, AVB (VBMeta digest/hash-alg/size/version), dm-verity error modes (incl. restart, bootconfig-aware), custom root of trust (verifiedbootstate=yellow), bootloader, integrity |
| **CRYPTOGRAPHY** | 20 | Encryption, keys, credentials, API keys, certificates, kernel entropy, Widevine DRM level |
| **MALWARE** | 18 | Root/Magisk/SuperSU, Frida, Xposed/LSPosed, RATs, keyloggers, memory scrapers, root cloaking |
| **CIS_BENCHMARK** | 17 | CIS Android Benchmark v1.6.0 controls (89% coverage) |
| **USB_SECURITY** | 16 | USB debugging, interfaces, serial ports, gadget mode |
| **CVE_INDICATORS** | 33 | Dirty Pipe, Bad Binder, Dirty COW, MTK-su, Exynos baseband, Mali GPU, kernel CVE ranges, WebView debugging |
| **DEVICE_MANAGEMENT** | 13 | MDM, accounts, developer options |
| **INPUT** | 12 | Keyboards, accessibility, input methods, IME INTERNET audit, kbd layout, clipboard auto-clear |
| **MEDICAL** | 11 | Medical device-specific checks, IEEE 11073 PHD pairing, PACS C-STORE, insulin/cardiac telemetry |
| **NFC_SECURITY** | 9 | NFC state, Android Beam, tap-to-pay, reader mode, secure element (eSE/UICC), tag write protection, HCE AID priority |
| **ADB_SECURITY** | 8 | ADB keys, network ADB allowlist, debugging, shell privilege, USB-debug notify, adbd integrity hash |
| **MODERN_ANDROID** | 9 | Android 13/14/15/16/17 surface: Photo Picker, READ_MEDIA_*, POST_NOTIFICATIONS, FGS type, Theft Detection Lock, Identity Check, Restricted Networking, Advanced Protection, A17 Local Network Access |
| **MDM_POLICY** | 15 | DevicePolicyManager state via dumpsys device_policy: management state, keyguard/camera policy, lock/wipe, password, audit logging, USB signaling, Common Criteria, MTE, app control, permission policy, Wi-Fi lockdown, A15 privacy, system update, permitted accessibility/input |
| **BIOMETRIC** | 5 | Fingerprint/face enrollment, biometric strength (Class 3 Strong vs Weak), biometric keyguard, auto-lock after biometric |

---

## Report Formats

Every run writes TXT, CSV, a detailed **XLSX** workbook and an interactive **HTML** dashboard (plus JSON with `--json-out`) into a timestamped folder under `--out`.

### Interactive HTML dashboard

- **Summary Dashboard** - total checks and per-severity counts (click a card to filter), doughnut chart
- **Deterministic Analysis card** - risk score, grade, attack chains, and the fix-in-order priorities
- **Device Information** - model, Android version, build, serial, SoC
- **Collapsible categories** with per-category severity badges
- **Per-check technical detail** - description, *why it matters*, *risk if failed*, *expected secure state*, the exact command and its output, remediation, and compliance chips (check ID, NIST 800-53, CIS, tags)
- **Certificate Audit Table** - CA certificates with expiry dates and risk status
- **Search & Filter** - find checks by label, description, ID, NIST control or tag

### Detailed XLSX workbook

A multi-sheet, audit-grade Excel workbook:

- **Summary** - risk score / grade / posture, findings-by-severity, device info, and a per-category breakdown
- **Findings** - one row per check with the full technical context (category, ID, label, status, level, why it matters, risk if failed, expected secure state, command, output, description, remediation, NIST 800-53, CIS, tags, baseline), colour-coded by severity, with a frozen header row and auto-filter
- **Certificates** - the CA certificate audit
- **Analysis** - correlated attack chains and the prioritised remediation order

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
| `baseline_key` | No | Opt the check into `--save-baseline` / `--baseline` tamper detection under this key (e.g. `vbmeta_digest`) |

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
    ├── analysis.py        # Deterministic risk engine (score, attack chains, prioritisation)
    ├── ai.py              # Optional opt-in LLM narrative (Ollama/Anthropic/OpenAI, stdlib only)
    ├── templates/
    │   └── report.html    # Interactive HTML report template
    └── commands/          # Security check definitions (777 checks, 28 categories)
        ├── system.json        #  86 checks - Kernel, TEE (QSEE/Mobicore/TEEGRIS/Trusty), SECCOMP, build, emulator, WebView
        ├── bluetooth.json     #  82 checks - BLE/Classic, pairing, all profiles
        ├── network.json       #  61 checks - Ports, WiFi, VPN, IoT protocols, Allow 2G, hotspot WPA
        ├── privacy.json       #  42 checks - Screen lock, location, sensors, clipboard, Restricted Settings
        ├── biometric.json     #   5 checks - Fingerprint/face enrollment, biometric strength (Strong/Weak), keyguard, auto-lock
        ├── apps.json          #  47 checks - Permissions, overlay, backup, install, APK signature scheme
        ├── binary_hardening.json # 36 checks - PIE, NX, RELRO, stack canaries, ASLR
        ├── partition.json     #  35 checks - dm-verity, A/B slots, FBE, mount flags (noexec/nosuid/nodev)
        ├── selinux.json       #  30 checks - Enforcement, policy version, audit
        ├── certificate_audit.json # 25 checks - CA certs, expiry, MITM
        ├── pos_security.json  #  24 checks - PCI-DSS, kiosk, NFC relay, PAX CVE
        ├── storage.json       #  24 checks - Encryption, partitions, backup
        ├── forensic_indicators.json # 22 checks - Crashes, logcat, temp artifacts
        ├── attestation.json   #  20 checks - SafetyNet/Play Integrity, Knox, Titan M, bypass detection
        ├── automotive.json    #  20 checks - Vehicle, CAN bus, infotainment
        ├── boot_security.json #  27 checks - Verified boot, AVB (VBMeta digest/hash/size/ver), dm-verity error modes, verifiedbootstate=yellow
        ├── cryptography.json  #  20 checks - Keystore, StrongBox, kernel entropy, Widevine DRM
        ├── malware.json       #  18 checks - Root, Frida, Xposed, RATs, scrapers
        ├── cis_benchmark.json #  17 checks - CIS Android Benchmark v1.6.0
        ├── usb_security.json  #  16 checks - USB debug, MTP, gadget mode
        ├── cve_indicators.json # 33 checks - Dirty Pipe, Bad Binder, MTK-su, kernel CVEs, WebView debug
        ├── device_management.json # 13 checks - MDM, accounts, dev options
        ├── input.json         #  12 checks - Keyboards, accessibility, IME INTERNET audit, kbd layout, clipboard auto-clear
        ├── medical.json       #  11 checks - Medical apps, IEEE 11073 PHD, PACS C-STORE, insulin/cardiac telemetry
        ├── nfc_security.json  #   9 checks - NFC, reader mode, secure element, tag write protection, HCE AID priority
        ├── adb_security.json  #   8 checks - ADB keys, network ADB allowlist, shell privilege, USB-debug notify, adbd integrity
        ├── modern_android.json #  9 checks - A13/A14/A15/16/17: Photo Picker, READ_MEDIA_*, POST_NOTIFICATIONS, FGS type, Theft/Identity, Restricted Networking, Advanced Protection, A17 Local Network Access
        └── mdm_policy.json    #  15 checks - DevicePolicyManager state (dumpsys device_policy): keyguard, camera, lock/wipe, logging, USB signaling, MTE, Wi-Fi lockdown, etc.
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
- [x] 6 AVB metadata-integrity checks - VBMeta digest, hash algorithm, size, required libavb version, managed dm-verity error-mode policy, and CONFIG_DM_VERITY_AVB kernel support (v5.12.0)
- [x] dm-verity `eio`/`panicking` false-positive fix: the AVB-recommended MANAGED_RESTART_AND_EIO mode is no longer flagged CRITICAL (v5.12.0)
- [x] Baseline tamper detection: `--save-baseline` / `--baseline` compare integrity values (VBMeta digest/size, adbd SHA-256) and flag any change CRITICAL (v5.13.0)
- [x] Android 17 Local Network Access (`ACCESS_LOCAL_NETWORK`) grant audit; dm-verity `restart` mode accepted; `/proc/bootconfig` (Android 12+) fallback on cmdline readers; verifiedbootstate=yellow (custom root of trust) surfaced as a distinct warning (v5.14.0)
- [x] Dedicated `BIOMETRIC` category: fingerprint/face/strength/keyguard/auto-lock checks split out of `PRIVACY` into `biometric.json` (v5.15.0)
- [x] Deterministic risk score (0-100) with grade, correlated attack chains and prioritised remediation, plus a `--profile` weighting flag (generic/pos/medical/kiosk/automotive/iot) (v5.10.0)
- [x] pytest suite (engine, analysis, AI redaction, helpers, reporters) + formal `hardax/commands.schema.json` validated in CI (v5.16.0)
- [x] Detailed XLSX report (Summary / Findings / Certificates / Analysis sheets) and richer HTML/CSV surfacing per-check technical context: why it matters, risk if failed, expected secure state, NIST/CIS mappings and tags (v5.17.0)
- [x] Fix a Windows-only stdout/stderr encoding crash, a CSV unbounded-result bug, 9 `binary_hardening.json` shell-precedence bugs (PIE/canary/RELRO/NX/FORTIFY checks), and CLI visibility for redirected/logged runs and narrow terminals - all found by running HARDAX end-to-end against a real device (v5.18.0)
- [x] CLI visual redesign: one rounded-corner box family reserved for panels that print once or redraw in place (banner, live HUD, final summary, final analysis), boxless hairline-rule category headers instead of a 3-line box repeated per category, a `❯_ HARDAX` wordmark, a strict two-role colour discipline (structure vs. severity), a guaranteed space between every status icon and its count (some terminal fonts render icons like ⚠ at double width), and terminal-width-aware truncation for `--show-commands` command/remediation lines so nothing needs horizontal scrolling - chosen from an independently-judged panel of 3 redesign directions and verified on both native Windows console and git-bash/mintty (v5.19.0)
- [x] 10 new checks from a 2025-2026 Android security feature gap analysis: null cipher protection (A14+) and cellular identifier disclosure notifications (A16+) - the first cellular-security checks in `network.json`; Certificate Transparency platform flags (A16+); Private Space profile (A15+); Intrusion Logging / Advanced Protection service state (A16+); Advanced Protection subfeature audit and KeyMint post-quantum readiness (A17+); io_uring restriction and 16KB page-size build (kernel); pKVM/AVF protected-VM support (v5.20.0)

### Open

Grouped by theme. Order within a group is rough priority.

#### Analysis features
- [ ] Full scan-to-scan diff (compare two complete audits, surface all finding regressions; integrity-value baselines already shipped via `--baseline` in v5.13.0)
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
- [ ] Inline remediation suggestions in the HTML report
- [ ] Multi-device parallel scanning
- [ ] Plugin architecture for custom check loaders
- [ ] Official Docker image with adb / paramiko / pyserial pre-installed
- [ ] Web dashboard (Flask / FastAPI) for centralised audit storage and history

#### Code quality
- [ ] Split the 2400-line `hardax/__init__.py` into modules (transports, engine, reporters, cli)
- [ ] Type hints throughout, clean under `mypy --strict`

#### External integration
- [ ] APK static analysis (apktool / jadx integration)
- [ ] SARIF output (for GitHub code scanning and similar tools)
