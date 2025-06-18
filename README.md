# Feather-Light Network Scanner (FLNS)

A comprehensive, lightweight Python-based network scanning tool designed for performing reconnaissance tasks such as port scanning, service detection, DNS lookup, subdomain enumeration, and basic web vulnerability assessment.  
Suitable for cybersecurity students, penetration testers, and network administrators.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Example](#example)
- [How It Works](#how-it-works)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Port Scanning**: TCP connect scans for specified or common ports.
- **Service Version Detection**: Identifies running services and versions (HTTP/S, SSH, FTP, SMTP).
- **Web Vulnerability Detection**:
  - Checks for missing HTTP security headers (CSP, HSTS, etc.).
  - Detects common sensitive files/directories (`robots.txt`, `.git/config`, etc.).
  - Basic XSS detection by parsing HTML.
- **DNS Information Lookup**: Retrieves A, AAAA, CNAME, MX, NS, SOA, TXT records, plus reverse DNS lookups.
- **Subdomain Enumeration**:
  - Brute-forces common subdomains.
  - Uses `crt.sh` to gather subdomains from Certificate Transparency logs.
- **Colored Output**: User-friendly colored terminal output for better readability.
- **Output Logging**: Saves detailed results in CSV format for later analysis.

## Requirements

- **Python** 3.x

### Required Python Libraries:

**requests** :  For making HTTP requests.

**beautifulsoup4** :  For parsing HTML content.

**colorama** :  For colored console output.

**dnspython** :  For advanced DNS queries.

## Installation

1. Clone this repository:

```bash
git clone https://github.com/CyberSamrat/FLNS-Project.git
cd FLNS_Project
```
2. Check if Python 3 is installed:
```bash
python3 --version
```
3. If Python 3 is not installed, install it via:
```bash
sudo apt-get update
sudo apt-get install python3
```
4. Install the required libraries:
```bash
pip install requests beautifulsoup4 colorama dnspython
```

## Usage
```bash
python3 flns.py
```

