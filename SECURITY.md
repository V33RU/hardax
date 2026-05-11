# Security Policy

HARDAX is a security auditing tool. If you discover a vulnerability in HARDAX
itself (not in the devices it audits), we want to know.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues privately via one of:

- GitHub Security Advisories: https://github.com/V33RU/hardax/security/advisories/new
- Email: open a private security advisory on GitHub (preferred)

When reporting, please include:

- A description of the issue and its potential impact
- Steps to reproduce
- The version of HARDAX affected (`python3 hardax.py --version`)
- Your environment (OS, Python version, ADB/SSH/UART mode)

## Response Expectations

This is a community-maintained project. We aim to acknowledge reports within
one week and to publish a fix or mitigation as soon as practical.

## Scope

In scope:
- The HARDAX engine (`hardax.py`)
- JSON check definitions in `commands/`
- The HTML/CSV/JSON report generation
- Command injection, path traversal, or credential-handling issues

Out of scope:
- Vulnerabilities in target devices (those are the *findings* HARDAX is
  designed to surface)
- Vulnerabilities in third-party dependencies (`paramiko`, `pyserial`,
  `cryptography`) — please report those upstream
