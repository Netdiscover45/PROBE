![Uploading ChatGPT Image Sep 24, 2026, 09_09_50 PM.png…]()

# PROBE

### Python Web Vulnerability Scanner

PROBE is a small Python-based web vulnerability scanner I built as a cybersecurity learning and portfolio project.

It focuses on understanding how a scanner collects HTTP information, performs security checks, creates findings and calculates basic risk.

**Authorized targets only.**

---

## Features

### Passive Checks

* Security headers
* Cookie security
* Redirects
* Server / `X-Powered-By` disclosure

### Controlled Active Checks

* HTTP `OPTIONS` / Allow header
* CORS
* Safe endpoint discovery

### Other

* Passive / Active / Full scan modes
* Basic risk scoring
* CLI interface
* Automated tests

---

## Installation

### Windows

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

### Linux

```bash
sudo apt update
sudo apt install -y git python3 python3-pip python3-venv

git clone https://github.com/Netdiscover45/PROBE.git
cd PROBE

python3 -m venv .venv
source .venv/bin/activate

python -m pip install -r requirements.txt
```

---

## Usage

Check version:

```bash
python -m probe.cli --version
```

Passive scan:

```bash
python -m probe.cli scan https://example.com --passive
```

Active scan:

```bash
python -m probe.cli scan https://example.com --active
```

Full scan:

```bash
python -m probe.cli scan https://example.com --full
```

Custom timeout:

```bash
python -m probe.cli scan https://example.com --full --timeout 15
```

---

## Testing

```bash
python -m pytest -q
```

Current test baseline: **28 passed**

---

## Project Structure

```text
Probe/
├── probe/
│   ├── cli.py
│   ├── scanner.py
│   ├── models.py
│   ├── scoring.py
│   ├── output.py
│   ├── Passive/
│   └── Active/
├── tests/
├── requirements.txt
├── README.md
└── LICENSE
```

---

## Risk Levels

```text
CRITICAL
HIGH
MEDIUM
LOW
INFO
```

These are project-level heuristic risk labels, not official CVSS scores.

---

## Safety

PROBE is intended only for systems you own or have explicit permission to test.

It does not perform brute-force attacks, destructive testing, DoS testing or automatic exploitation.

---

## Status

**Version: 0.1**

PROBE is a work in progress. More security checks, testing and improvements will be added over time.

---
## Why I Built PROBE

I built PROBE as a personal cybersecurity learning project to understand how web vulnerability scanners work internally.

Through this project, I am learning about HTTP requests, security headers, CORS, cookies, automated security checks, risk scoring and Python-based security tool development.

The goal is to keep improving PROBE while building a practical understanding of web security.
---
## Author

Built by Netdiscover45  as a personal cybersecurity learning and portfolio project.
