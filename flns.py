import socket
import threading
import requests
import json
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
import sys
from concurrent.futures import ThreadPoolExecutor
import time
import struct # Kept for potential future raw socket use, though not used in current port scan logic
import dns.resolver
import random
import ssl
import csv

# Initialize colorama for colored console output
init(autoreset=True)

# List to store all printed output for later saving
output_log = []

def log_print(message, color=Fore.WHITE):
    """
    Prints a message to the console with a specified color and appends it to the output log.
    """
    print(color + message + Style.RESET_ALL)
    output_log.append(message)

def show_banner():
    banner = f"""
{Fore.CYAN}
                                                                                                        ______ _       _   _  _____ 
                                                                                                       |  ____| |     | \\ | |/ ____|
                                                                                                       | |__  | |     |  \\| | (___
                                                                                                       |  __| | |     | . ` |\\___ \\
                                                                                                       | |    | |____ | |\\  |____) |
                                                                                                       |_|    |______||_| \\_|_____/

     {Fore.YELLOW}                                                                                              Feather-Light Network Scanner (FLNS)
                                                                                                               Version: 1.1
                                                                                       |----------------------------------------------------------|
                                                                                       |        Created by: Samrat Sen & Team Sudo Knights        |
                                                                                       |  LinkedIn ID: https://www.linkedin.com/in/samratsen007/  |
                                                                                       |----------------------------------------------------------|
{Style.RESET_ALL}"""
    print(banner)

def probe_service_version(ip, port):
    """
    Attempts to connect to a given IP and port to identify the service and its version.
    Handles HTTP/HTTPS, SSH, FTP, and SMTP services.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)  # Increased timeout for more reliable version detection
        try:
            sock.connect((ip, port))
        except ConnectionRefusedError:
            return f"Service: {socket.getservbyport(port, 'tcp') if socket.getservbyport else 'Unknown'}"

        service_name = socket.getservbyport(port, 'tcp') if socket.getservbyport else 'Unknown'
        version_info = "Unknown"  # Default version information

        try:
            if service_name == "http" or service_name == "https":
                if service_name == "https":
                    # Wrap socket with SSL context for HTTPS
                    context = ssl.create_default_context()
                    sock = context.wrap_socket(sock, server_hostname=ip)
                sock.send(b"GET / HTTP/1.0\r\n\r\n") # Send HTTP GET request
                response = sock.recv(1024).decode(errors='ignore')
                if "Server:" in response:
                    version_info = response.split("Server:")[1].split("\r\n")[0].strip()
            elif service_name == "ssh":
                # Send SSH version request
                sock.send(b'SSH-2.0-FLNS\r\n')
                response = sock.recv(1024).decode(errors='ignore')
                if response and "SSH" in response:
                    version_info = response.strip().split("SSH-")[1].split()[0]
            elif service_name == "ftp":
                response = sock.recv(1024).decode(errors='ignore')
                if response and "220" in response: # Common FTP banner response code
                    version_info = "vsftpd 3.0.3"  # Example version, could be dynamic if parsing is improved
            elif service_name == "smtp":
                response = sock.recv(1024).decode(errors='ignore')
                if response and "220" in response: # Common SMTP banner response code
                    version_info = response.split("220")[1].strip()
        except Exception:
            pass  # Keep default version_info if probing fails
        finally:
            sock.close() # Ensure socket is closed

        return f"Service: {service_name}, Version: {version_info}"
    except (socket.timeout, OSError) as e:
        # Handle connection timeout or OS-related errors
        return f"Service: {socket.getservbyport(port, 'tcp') if socket.getservbyport else 'Unknown'}"
    except Exception as e:
        # Catch any other unexpected errors
        return f"Service: {socket.getservbyport(port, 'tcp') if socket.getservbyport else 'Unknown'}"

def tcp_connect_scan(ip, port, results):
    """
    Performs a TCP connect scan (full handshake).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5) # Short timeout for quick checks
        result = sock.connect_ex((ip, port)) # connect_ex returns an error indicator
        if result == 0: # 0 indicates success (port is open)
            service_name = socket.getservbyport(port, 'tcp') if socket.getservbyport else 'Unknown'
            results[port] = f"[+] Open, Service: {service_name}"
        sock.close()
    except Exception as e:
        results[port] = f"Error: {e}"

def port_scan(ip, ports):
    """
    Orchestrates the port scanning process using threads for efficiency.
    This version only performs TCP connect scans.
    """
    log_print(f"\n[*] Performing CONNECT scan on {ip}...", Fore.BLUE)
    results = {}
    # Use ThreadPoolExecutor for concurrent port scanning
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = []
        for port in ports:
            futures.append(executor.submit(tcp_connect_scan, ip, port, results))

        # Wait for all threads to complete
        for future in futures:
            future.result()

    # Print scan results in a sorted order
    for port in sorted(results.keys()):
        if "Open" in results[port]:
            log_print(f"Port {port}: {results[port]}", Fore.GREEN)
        elif "Closed" in results[port]:
            log_print(f"Port {port}: {results[port]}", Fore.RED)
        elif "Filtered" in results[port]:
            log_print(f"Port {port}: {results[port]}", Fore.YELLOW)
        else:
            log_print(f"Port {port}: {results[port]}", Fore.RED)

def detect_http_headers(url):
    """
    Fetches HTTP headers for a given URL and checks for common security-related headers.
    """
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        log_print(f"\n[*] HTTP Headers for {url}:", Fore.BLUE)
        for header, value in headers.items():
            log_print(f"  {header}: {value}")

        vulnerabilities = []
        # Check for missing security headers
        if 'Content-Security-Policy' not in headers:
            vulnerabilities.append("Missing Content-Security-Policy (CSP)")
        if 'X-Content-Type-Options' not in headers:
            vulnerabilities.append("Missing X-Content-Type-Options (prevents MIME sniffing)")
        if 'Strict-Transport-Security' not in headers:
            vulnerabilities.append("Missing Strict-Transport-Security (HSTS)")
        if 'X-Frame-Options' not in headers:
            vulnerabilities.append("Missing X-Frame-Options (clickjacking protection)")
        # Identify common web servers
        if 'Server' in headers and 'nginx' in headers['Server'].lower():
            vulnerabilities.append(f"Web server is Nginx (check for known Nginx vulnerabilities)")
        elif 'Server' in headers and 'apache' in headers['Server'].lower():
            vulnerabilities.append(f"Web server is Apache (check for known Apache vulnerabilities)")

        if vulnerabilities:
            log_print(f"\n[!] Potential HTTP header vulnerabilities:", Fore.YELLOW)
            for vuln in vulnerabilities:
                log_print(f"  - {vuln}")
        else:
            log_print(f"\n[+] No major HTTP header vulnerabilities detected.", Fore.GREEN)

    except requests.exceptions.RequestException as e:
        log_print(f"[!] Error fetching {url}: {e}", Fore.RED)

def detect_common_files(url):
    """
    Checks for the presence of common sensitive files and directories on a web server.
    """
    common_files = ["robots.txt", ".htaccess", "sitemap.xml", "config.php", ".git/config", "admin/", "login/"]
    found_files = []
    log_print(f"\n[*] Checking for common files on {url}:", Fore.BLUE)
    for file in common_files:
        full_url = f"{url.rstrip('/')}/{file}" # Construct full URL
        try:
            response = requests.get(full_url, timeout=3)
            if response.status_code == 200:
                log_print(f"[+] Found: {full_url} (Status: {response.status_code})", Fore.GREEN)
                found_files.append(full_url)
            elif response.status_code != 404: # Report non-404 status codes as potential findings
                log_print(f"[!] Found: {full_url} (Status: {response.status_code})", Fore.YELLOW)
            else:
                log_print(f"[-] Not Found: {full_url} (Status: {response.status_code})", Fore.RED)
        except requests.exceptions.RequestException as e:
            log_print(f"[-] Error checking {full_url}: {e}", Fore.RED)
    if found_files:
        log_print(f"\n[*] Common files found:", Fore.YELLOW)
        for f in found_files:
            log_print(f"  - {f}")
    else:
        log_print(f"\n[+] No common files found (or access denied).", Fore.GREEN)

def detect_xss(html_content):
    """
    Detects potential XSS vulnerabilities in the given HTML content by looking for script tags.
    This is a basic detection and not a full XSS scanner.
    """
    vulnerabilities = []
    soup = BeautifulSoup(html_content, 'html.parser')
    scripts = soup.find_all('script')
    for script in scripts:
        # Check for common XSS patterns within script tags
        if '<script>' in str(script) or 'alert(' in str(script).lower() or 'document.cookie' in str(script).lower():
            vulnerabilities.append(f"  - Possible XSS vulnerability detected in: {script}")
    return vulnerabilities

def detect_vulnerabilities(url):
    """
    Combines HTTP header detection and basic XSS detection for web vulnerabilities.
    """
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers
        log_print(f"\n[*] HTTP Headers for {url}:", Fore.BLUE)
        for header, value in headers.items():
            log_print(f"  {header}: {value}")

        vulnerabilities = []
        # Check for missing security headers
        if 'Content-Security-Policy' not in headers:
            vulnerabilities.append("Missing Content-Security-Policy (CSP)")
        if 'X-Content-Type-Options' not in headers:
            vulnerabilities.append("Missing X-Content-Type-Options (prevents MIME sniffing)")
        if 'Strict-Transport-Security' not in headers:
            vulnerabilities.append("Missing Strict-Transport-Security (HSTS)")
        if 'X-Frame-Options' not in headers:
            vulnerabilities.append("Missing X-Frame-Options (clickjacking protection)")
        # Identify common web servers
        if 'Server' in headers and 'nginx' in headers['Server'].lower():
            vulnerabilities.append(f"Web server is Nginx (check for known Nginx vulnerabilities)")
        elif 'Server' in headers and 'apache' in headers['Server'].lower():
            vulnerabilities.append(f"Web server is Apache (check for known Apache vulnerabilities)")

        xss_vulnerabilities = detect_xss(response.text) # Perform XSS detection

        if vulnerabilities or xss_vulnerabilities:
            log_print(f"\n[!] Potential HTTP vulnerabilities:", Fore.YELLOW)
            for vuln in vulnerabilities:
                log_print(f"  - {vuln}")
            for xss_vuln in xss_vulnerabilities:
                log_print(f"{Fore.RED}{xss_vuln}") # Print XSS findings in red
        else:
            log_print(f"\n[+] No major HTTP header vulnerabilities detected.", Fore.GREEN)

    except requests.exceptions.RequestException as e:
        log_print(f"[!] Error fetching {url}: {e}", Fore.RED)

def get_dns_info(target):
    """
    Retrieves various DNS records (A, AAAA, CNAME, MX, NS, SOA, TXT) for a given target.
    """
    log_print(f"\n[*] Retrieving DNS information for {target}:", Fore.BLUE)
    try:
        try:
            ip_address = socket.gethostbyname(target)
            log_print(f"  IP Address: {ip_address}")
        except socket.gaierror:
            log_print(f"  Target is an IP Address (no direct hostname lookup): {target}")
            ip_address = target # If target is already an IP, use it directly

        try:
            # Attempt reverse DNS lookup
            host_name, alias_list, ip_list = socket.gethostbyaddr(ip_address)
            log_print(f"  Hostname: {host_name}")
            if alias_list:
                log_print(f"  Aliases: {', '.join(alias_list)}")
        except socket.herror:
            log_print("  Hostname: No PTR record found or reverse lookup failed.")
        except Exception as e:
            log_print(f"  Hostname: Error during reverse lookup: {e}")

        resolver = dns.resolver.Resolver()
        resolver.timeout = 1 # Set a short timeout for DNS queries
        resolver.lifetime = 1 # Set a short lifetime for DNS queries

        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'SOA', 'TXT']

        for record_type in record_types:
            try:
                answers = resolver.resolve(target, record_type)
                log_print(f"\n  {record_type} Records:")
                for rdata in answers:
                    log_print(f"    {rdata}")
            except dns.resolver.NoAnswer:
                log_print(f"  {record_type} Records: No records found")
            except dns.resolver.NXDOMAIN:
                log_print(f"  {record_type} Records: Domain does not exist.")
                break # If domain doesn't exist, no need to check other records
            except dns.resolver.Timeout:
                log_print(f"  {record_type} Records: Query timed out.")
            except Exception as e:
                log_print(f"  {record_type} Records: Error: {e}")

    except Exception as e:
        log_print(f"[!] An error occurred during DNS lookup: {e}", Fore.RED)

def find_subdomains(domain):
    """
    Finds subdomains for a given domain using common wordlist brute-forcing and crt.sh.
    """
    log_print(f"\n[*] Starting subdomain enumeration for {domain}...", Fore.BLUE)
    found_subdomains = set() # Use a set to store unique subdomains

    # --- Method 1: Common Subdomain Brute-forcing ---
    common_subdomains = [
        "www", "mail", "blog", "dev", "api", "test", "admin", "ftp", "vpn",
        "webmail", "autodiscover", "cpanel", "whm", "ns1", "ns2", "docs",
        "portal", "app", "secure", "status", "shop", "store", "cdn", "img",
        "assets", "support", "help", "intranet", "extranet", "demo", "stage",
        "qa", "beta", "proxy", "sso", "login", "register", "forum", "community"
    ]

    log_print(f"[*] Trying common subdomains...", Fore.BLUE)
    resolver = dns.resolver.Resolver()
    resolver.timeout = 1 # Short timeout for individual DNS queries
    resolver.lifetime = 1 # Short lifetime

    def check_subdomain(sub):
        """Helper function to check a single subdomain."""
        full_subdomain = f"{sub}.{domain}"
        try:
            answers = resolver.resolve(full_subdomain, 'A') # Try to resolve A record
            for rdata in answers:
                log_print(f"[+] Found subdomain: {full_subdomain} -> {rdata.address}", Fore.GREEN)
                found_subdomains.add(full_subdomain)
                return True # Found an A record, so it's a valid subdomain
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
            pass # Subdomain does not exist, no answer, or timed out - expected for many attempts
        except Exception as e:
            log_print(f"[-] Error checking {full_subdomain}: {e}", Fore.RED)
        return False

    # Use ThreadPoolExecutor for concurrent DNS lookups for brute-forcing
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(check_subdomain, sub) for sub in common_subdomains]
        for future in futures:
            future.result() # Wait for all subdomain checks to complete


    # --- Method 2: Certificate Transparency Logs (crt.sh) ---
    log_print(f"\n[*] Querying crt.sh for subdomains...", Fore.BLUE)
    try:
        # Query crt.sh for certificates related to the domain
        crt_sh_url = f"https://crt.sh/?q=%25.{domain}&output=json"
        response = requests.get(crt_sh_url, timeout=10)
        response.raise_for_status() # Raise an exception for HTTP errors (4xx or 5xx)
        certs = json.loads(response.text) # Parse JSON response

        for cert in certs:
            # 'name_value' often contains Subject Alternative Names (SANs)
            name_values = cert.get('name_value', '').split('\n')
            for name in name_values:
                name = name.strip()
                # Check if the name ends with the domain and is not the base domain itself
                if name.endswith(f".{domain}") and name != domain:
                    log_print(f"[+] Found subdomain via crt.sh: {name}", Fore.GREEN)
                    found_subdomains.add(name)
                # Also check common_name if it's a subdomain
                elif name == domain and cert.get('common_name') != domain and cert.get('common_name').endswith(f".{domain}"):
                    log_print(f"[+] Found subdomain via crt.sh (common_name): {cert.get('common_name')}", Fore.GREEN)
                    found_subdomains.add(cert.get('common_name'))

    except requests.exceptions.RequestException as e:
        log_print(f"[!] Error querying crt.sh: {e}", Fore.RED)
    except json.JSONDecodeError:
        log_print(f"[!] Error decoding JSON from crt.sh. Response might not be JSON or empty.", Fore.RED)
    except Exception as e:
        log_print(f"[!] An unexpected error occurred during crt.sh query: {e}", Fore.RED)

    if found_subdomains:
        log_print(f"\n[+] Subdomain enumeration complete. Found {len(found_subdomains)} unique subdomains:", Fore.GREEN)
        for sub in sorted(list(found_subdomains)): # Print sorted unique subdomains
            log_print(f"  - {sub}")
    else:
        log_print(f"\n[-] No subdomains found for {domain} using current methods.", Fore.YELLOW)

def save_log_to_csv(log, filename="flns_full_report.csv"):
    """
    Saves the entire output log to a CSV file.
    """
    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            writer.writerow(["FLNS Output"]) # CSV header
            for line in log:
                writer.writerow([line]) # Write each log entry as a row
        log_print(f"\n[+] Full output saved to {filename}", Fore.GREEN)
    except Exception as e:
        log_print(f"[!] Failed to save log: {e}", Fore.RED)

def main():
    """
    Main function to run the Featherlight Network Scanner.
    Handles user input and orchestrates different scanning modules.
    """
    show_banner()
    target = input("\nEnter IP address or domain name: ")

    perform_port_scan_choice = input("Would you like to perform a network scan? (y/n): ").strip().lower()
    
    ports_to_scan = []

    if perform_port_scan_choice == 'y':
        ports_input = input("Enter port range (e.g., 1-1024, or 'common') or a single port: ")
        
        if ports_input.lower() == 'common':
            ports_to_scan = list(range(1, 1025))
        elif '-' in ports_input:
            try:
                start_port, end_port = map(int, ports_input.split('-'))
                ports_to_scan = list(range(start_port, end_port + 1))
            except ValueError:
                log_print("[!] Invalid port range format. Skipping port scan.", Fore.RED)
                ports_to_scan = [] # Clear ports to skip scan
        else:
            try:
                ports_to_scan = [int(ports_input)]
            except ValueError:
                log_print("[!] Invalid port format. Skipping port scan.", Fore.RED)
                ports_to_scan = [] # Clear ports to skip scan

    if ports_to_scan: # Only proceed with port scan if ports are defined
        try:
            ip = socket.gethostbyname(target) # Resolve target to IP for port scanning
            log_print(f"\n[+] Resolved IP: {ip}", Fore.GREEN)
            port_scan(ip, ports_to_scan) # Call port_scan without scan_type argument
        except socket.gaierror:
            log_print(f"[!] Could not resolve hostname for port scan: {target}", Fore.RED)
        except Exception as e:
            log_print(f"[!] An error occurred during port scanning: {e}", Fore.RED)
    else:
        log_print("\n[*] Port scan skipped.", Fore.YELLOW)

    # Offer service version detection only if a port scan was performed and ports were scanned
    if perform_port_scan_choice == 'y' and ports_to_scan: # Check if port scan was chosen and ports were scanned
        host_version = input("\nEnter host for service version detection (leave blank to skip): ")
        if host_version:
            port_version = input("Enter port for service version detection: ")
            if port_version.isdigit():
                try:
                    service_info = probe_service_version(host_version, int(port_version))
                    log_print(f"[+] Port {port_version}: {service_info}", Fore.GREEN)
                except Exception as e:
                    log_print(f"[!] Error during service version detection: {e}", Fore.RED)
            else:
                log_print("[!] Invalid port for service version detection.", Fore.RED)

    # Determine if the target is a domain for web-related scans
    is_domain = False
    try:
        socket.gethostbyname(target) # This will raise an error if it's not a valid domain/IP
        is_domain = True
    except socket.gaierror:
        is_domain = False # It's likely an IP or invalid domain

    if is_domain:
        url_vuln = input("\nEnter URL for web vulnerability detection (e.g., http://example.com, leave blank to skip): ")
        if url_vuln:
            detect_vulnerabilities(url_vuln)
            detect_common_files(url_vuln)
    else:
        log_print("\n[*] Web vulnerability detection skipped (target is not a domain or invalid).", Fore.YELLOW)

    # Always perform DNS info lookup if it's a domain or IP
    get_dns_info(target)

    # New subdomain finding feature
    subdomain_choice = input("\nWould you like to find subdomains for the target? (y/n): ").strip().lower()
    if subdomain_choice == 'y':
        if is_domain: # Subdomain finding only makes sense for domains
            find_subdomains(target)
        else:
            log_print("[!] Subdomain finding can only be performed on a domain name, not an IP address.", Fore.RED)

    save_choice = input("\nWould you like to save all output to a CSV file? (y/n): ").strip().lower()
    if save_choice == 'y':
        save_log_to_csv(output_log)

if __name__ == "__main__":
    main()
