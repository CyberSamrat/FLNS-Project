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

**requests** :-   For making HTTP requests.

**beautifulsoup4** :-   For parsing HTML content.

**colorama** :-   For colored console output.

**dnspython** :-   For advanced DNS queries.

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

## Example
```yaml
command: "python3 flns.py"
  banner: 
                   ______ _       _   _  _____
                  |  ____| |     | \ | |/ ____|
                  | |__  | |     |  \| | (___
                  |  __| | |     | . ` |\___ \
                  | |    | |____ | |\  |____) |
                  |_|    |______||_| \_|_____/

              Feather-Light Network Scanner (FLNS)
                         Version: 1.1
   |----------------------------------------------------------|
   |        Created by: Samrat Sen & Team Sudo Knights        |
   |  LinkedIn ID: https://www.linkedin.com/in/samratsen007/  |
   |----------------------------------------------------------|
steps:
  - prompt: "Enter IP address or domain name"
    input: "example.com"
  - prompt: "Would you like to perform a network scan? (y/n)"
    input: "y"
  - prompt: "Enter port range (e.g., 1-1024, or 'common') or a single port"
    input: "common"
  - output:
      resolved_ip: "93.184.216.34"
      scan_type: "CONNECT scan"
      ports:
        - port: 80
          status: "Open"
          service: "http"
        - port: 443
          status: "Open"
          service: "https"
        - port: 21
          status: "Not Found"
          note: "robots.txt (Status: 404)"
  - prompt: "Enter host for service version detection (leave blank to skip)"
    input: "93.184.216.34"
  - prompt: "Enter port for service version detection"
    input: "80"
  - output:
      service_detection:
        port: 80
        service: "http"
        version: "Apache"
  - prompt: "Enter URL for web vulnerability detection (leave blank to skip)"
    input: "http://example.com"
  - output:
      http_headers:
        Date: "Wed, 18 Jun 2025 12:34:56 GMT"
        Server: "ECS (iad/1409)"
        Content-Type: "text/html"
        Content-Length: "1256"
        Last-Modified: "Fri, 09 Aug 2019 13:30:17 GMT"
        Etag: "\"5d4ddc49-4e0\""
        Accept-Ranges: "bytes"
      vulnerabilities:
        - "Missing Content-Security-Policy (CSP)"
        - "Missing X-Content-Type-Options (prevents MIME sniffing)"
        - "Missing Strict-Transport-Security (HSTS)"
        - "Missing X-Frame-Options (clickjacking protection)"
  - output:
      common_files_check:
        found:
          - "http://example.com/robots.txt (Status: 200)"
        not_found:
          - "http://example.com/.htaccess (Status: 404)"
  - output:
      dns_information:
        ip_address: "93.184.216.34"
        hostname: "example.com"
        a_records:
          - "93.184.216.34"
        mx_records: "No records found"
  - prompt: "Would you like to find subdomains for the target? (y/n)"
    input: "y"
  - output:
      subdomain_enumeration:
        brute_force:
          - "www.example.com (Status: 404)"
        crtsh_results:
          - "mail.example.com"
        unique_subdomains:
          - "mail.example.com"
  - prompt: "Would you like to save all output to a CSV file? (y/n)"
    input: "y"
  - output:
      saved_file: "flns_full_report.csv"
```
## How It Works

The script provides a menu-driven interface to perform various network reconnaissance tasks:

- **Port Scanning**:  
  Uses `socket` to establish TCP connections to specified ports.  
  It leverages `concurrent.futures.ThreadPoolExecutor` for efficient concurrent scanning.

- **Service Version Detection**:  
  Attempts to send protocol-specific probes (e.g., HTTP GET, SSH banner request) to open ports and parses the responses to identify the service and its version.  
  `ssl` is used for HTTPS connections.

- **Web Vulnerability Detection**:
  - Uses the `requests` library to fetch HTTP headers and checks for the presence or absence of key security headers.
  - Performs `requests.get` calls for common sensitive file paths.
  - `BeautifulSoup` is used to parse the HTML content for rudimentary XSS detection by searching for common script patterns.

- **DNS Information Lookup**:  
  Employs the `dnspython` library to query various DNS record types (`A`, `AAAA`, `CNAME`, `MX`, `NS`, `SOA`, `TXT`).  
  It also performs reverse DNS lookups using `socket.gethostbyaddr`.

- **Subdomain Enumeration**:  
  Combines two methods:
  - **Brute-forcing**: Iterates through a predefined list of common subdomain prefixes and attempts to resolve their `A` records using `dnspython`.
  - **CRT.sh Query**: Makes an HTTP request to `crt.sh`, a Certificate Transparency log search engine, to find subdomains mentioned in SSL/TLS certificates issued for the target domain.

- **Output Management**:  
  All console output is captured and can be saved to a CSV file using the `csv` module, providing a persistent record of the scan results.
## Contributing

Pull requests are welcome.  
For major changes, please open an issue first to discuss what you would like to change.

## License

This project is licensed under the **Apache License, Version 2.0**.  
See the [LICENSE](LICENSE) file for details.

---

**Created by:** Samrat Sen & Team Sudo Knights  
**LinkedIn:** [https://www.linkedin.com/in/samratsen007/](https://www.linkedin.com/in/samratsen007/)
