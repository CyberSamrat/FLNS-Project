FLNS Project: Feather-Light Network Scanner
This Python script is a comprehensive and easy-to-use network scanning tool designed for various reconnaissance tasks. It allows users to perform port scans, detect web vulnerabilities, retrieve DNS information, and enumerate subdomains for a given target.

Features
Port Scanning: Supports TCP connect scans for specified ports or common port ranges.

Service Version Detection: Identifies services and their versions running on open ports (HTTP/S, SSH, FTP, SMTP).

Web Vulnerability Detection:

Analyzes HTTP headers for missing security policies (CSP, HSTS, X-Frame-Options, X-Content-Type-Options).

Checks for common sensitive files and directories (e.g., robots.txt, .git/config, admin/).

Basic XSS (Cross-Site Scripting) detection by looking for script patterns in HTML content.

DNS Information Lookup: Retrieves A, AAAA, CNAME, MX, NS, SOA, and TXT records, along with reverse DNS lookups.

Subdomain Enumeration: Finds subdomains using common wordlist brute-forcing and queries against Certificate Transparency logs (crt.sh).

Colored Output: Provides clear, color-coded output for better readability.

Output Logging: Saves all scan output to a CSV file for detailed reporting.

Requirements
Python 3.x

requests library: For making HTTP requests.

bs4 (BeautifulSoup) library: For parsing HTML content.

colorama library: For colored console output.

dnspython library: For advanced DNS queries.

Installation
Clone the repository:

git clone https://github.com/CyberSamrat/FLNS_project.git
cd FLNS_project

Make sure you have Python 3 installed:
Most Kali Linux distributions come with Python 3 pre-installed. You can verify with:

python3 --version

If not installed, you can get it via:

sudo apt-get update
sudo apt-get install python3

Install the required Python libraries:

pip install requests beautifulsoup4 colorama dnspython

Usage
Run the script from your terminal:

python3 flns.py

The script will prompt you for the target IP address or domain name and guide you through various scanning options:

Network Scan (Port Scan): You'll be asked if you want to perform a port scan. If yes, you can specify a port range (e.g., 1-1024), a single port (e.g., 80), or type common for well-known ports (1-1024).

Service Version Detection: After a port scan, you can choose to detect service versions on a specific host and port.

Web Vulnerability Detection: If the target is a domain, you'll be prompted to enter a URL (e.g., http://example.com) to check for web vulnerabilities and common files.

Subdomain Finding: You'll have an option to enumerate subdomains for domain targets.

Save Output: At the end, you can choose to save the entire scan output to a CSV file (flns_full_report.csv).

Example Interaction
$ python3 flns.py
                                                                                   ______ _       _   _  _____
                                                                                 |  ____| |     | \ | |/ ____|
                                                                                 | |__  | |     |  \| | (___
                                                                                 |  __| | |     | . ` |\___ \
                                                                                 | |    | |____ | |\  |____) |
                                                                                 |_|    |______||_| \_|_____/

                                                                            Feather-Light Network Scanner (FLNS)
                                                                                        Version: 1.1
                                                                |----------------------------------------------------------|
                                                                |  Created by: Samrat Sen & Team Sudo Knights              |
                                                                |  LinkedIn ID: https://www.linkedin.com/in/samratsen007/  |
                                                                |----------------------------------------------------------|

Enter IP address or domain name: example.com
Would you like to perform a network scan? (y/n): y
Enter port range (e.g., 1-1024, or 'common') or a single port: common

[*] Resolved IP: 93.184.216.34
[*] Performing CONNECT scan on 93.184.216.34...
Port 80: [+] Open, Service: http
Port 443: [+] Open, Service: https
Port 21: [-] Not Found: http://example.com/robots.txt (Status: 404)
... (more port scan results) ...

Enter host for service version detection (leave blank to skip): 93.184.216.34
Enter port for service version detection: 80
[+] Port 80: Service: http, Version: Apache

Enter URL for web vulnerability detection (e.g., http://example.com, leave blank to skip): http://example.com

[*] HTTP Headers for http://example.com:
  Date: Wed, 18 Jun 2025 12:34:56 GMT
  Server: ECS (iad/1409)
  Content-Type: text/html
  Content-Length: 1256
  Last-Modified: Fri, 09 Aug 2019 13:30:17 GMT
  Etag: "5d4ddc49-4e0"
  Accept-Ranges: bytes
  Missing Content-Security-Policy (CSP)
  Missing X-Content-Type-Options (prevents MIME sniffing)
  Missing Strict-Transport-Security (HSTS)
  Missing X-Frame-Options (clickjacking protection)
[!] Potential HTTP header vulnerabilities:
  - Missing Content-Security-Policy (CSP)
  - Missing X-Content-Type-Options (prevents MIME sniffing)
  - Missing Strict-Transport-Security (HSTS)
  - Missing X-Frame-Options (clickjacking protection)

[*] Checking for common files on http://example.com:
[+] Found: http://example.com/robots.txt (Status: 200)
[-] Not Found: http://example.com/.htaccess (Status: 404)
... (more common file checks) ...

[*] Retrieving DNS information for example.com:
  IP Address: 93.184.216.34
  Hostname: example.com
  A Records:
    93.184.216.34

  MX Records: No records found
  ... (more DNS records) ...

Would you like to find subdomains for the target? (y/n): y

[*] Starting subdomain enumeration for example.com...
[*] Trying common subdomains...
[-] Not Found: www.example.com (Status: 404)
... (more common subdomain checks) ...
[*] Querying crt.sh for subdomains...
[+] Found subdomain via crt.sh: mail.example.com
... (more crt.sh findings) ...

[+] Subdomain enumeration complete. Found 1 unique subdomains:
  - mail.example.com

Would you like to save all output to a CSV file? (y/n): y

[+] Full output saved to flns_full_report.csv

How It Works
The script provides a menu-driven interface to perform various network reconnaissance tasks:

Port Scanning: Uses socket to establish TCP connections to specified ports. It leverages concurrent.futures.ThreadPoolExecutor for efficient concurrent scanning.

Service Version Detection: Attempts to send protocol-specific probes (e.g., HTTP GET, SSH banner request) to open ports and parses the responses to identify the service and its version. ssl is used for HTTPS connections.

Web Vulnerability Detection:

Uses the requests library to fetch HTTP headers and checks for the presence or absence of key security headers.

Performs requests.get calls for common sensitive file paths.

BeautifulSoup is used to parse the HTML content for rudimentary XSS detection by searching for common script patterns.

DNS Information Lookup: Employs the dnspython library to query various DNS record types (A, AAAA, CNAME, MX, NS, SOA, TXT). It also performs reverse DNS lookups using socket.gethostbyaddr.

Subdomain Enumeration: Combines two methods:

Brute-forcing: Iterates through a predefined list of common subdomain prefixes and attempts to resolve their A records using dnspython.

CRT.sh Query: Makes an HTTP request to crt.sh, a Certificate Transparency log search engine, to find subdomains mentioned in SSL/TLS certificates issued for the target domain.

Output Management: All console output is captured and can be saved to a CSV file using the csv module, providing a persistent record of the scan results.
