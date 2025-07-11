#!/usr/bin/env python3
# filepath: Scripts/EnhancedCVEScanner.py

import csv
import subprocess
import os
import json
import time
import re
import socket
from datetime import datetime
import argparse
import requests
import sys

def get_cve_url(cve_id):
    """Generate a URL to the NIST NVD page for a given CVE."""
    return f"https://nvd.nist.gov/vuln/detail/{cve_id}"

def extract_severity(text):
    """Extract CVSS score and severity from vulnerability description."""
    # Look for CVSS score patterns like "CVSS: 9.8/10" or "CVSS:9.8"
    cvss_pattern = re.compile(r'CVSS:?\s*(\d+\.\d+)')
    cvss_match = cvss_pattern.search(text)
    
    cvss_score = float(cvss_match.group(1)) if cvss_match else None
    
    # Look for severity words
    severity = "Unknown"
    if "critical" in text.lower():
        severity = "Critical"
    elif "high" in text.lower():
        severity = "High"
    elif "medium" in text.lower():
        severity = "Medium"
    elif "low" in text.lower():
        severity = "Low"
    
    # If we have a CVSS score but no explicit severity, derive it
    if cvss_score is not None and severity == "Unknown":
        if cvss_score >= 9.0:
            severity = "Critical"
        elif cvss_score >= 7.0:
            severity = "High"
        elif cvss_score >= 4.0:
            severity = "Medium"
        else:
            severity = "Low"
            
    return cvss_score, severity

def scan_port_for_vulnerabilities(target, port, verbose=True):
    """Scan a specific port on a target for vulnerabilities."""
    cve_findings = []
    
    try:
        # Run vulnerability scan for the specific port
        command = ['nmap', '--script', 'vuln', '-p', port, target]
        if verbose:
            print(f"[*] Running: {' '.join(command)}")
            
        vuln_process = subprocess.run(command, capture_output=True, text=True, timeout=180)
        
        if vuln_process.returncode != 0:
            if verbose:
                print(f"[!] Vulnerability scan failed for {target}:{port}")
            return cve_findings
        
        vuln_output = vuln_process.stdout
        
        # Look for CVE identifiers
        current_cve = None
        cve_details = []
        
        for line in vuln_output.splitlines():
            # New CVE found
            if 'CVE-' in line:
                # Save previous CVE if exists
                if current_cve:
                    details_text = '\n'.join(cve_details)
                    cvss, severity = extract_severity(details_text)
                    cve_findings.append({
                        'id': current_cve,
                        'details': details_text,
                        'url': get_cve_url(current_cve),
                        'cvss': cvss,
                        'severity': severity,
                        'port': port,
                        'target': target
                    })
                    if verbose:
                        sev_str = f" [{severity}" + (f", CVSS: {cvss}" if cvss else "") + "]"
                        print(f"[+] Found vulnerability: {current_cve}{sev_str}")
                
                # Extract new CVE
                current_cve = line[line.find('CVE-'):].split()[0].rstrip(':,')
                cve_details = [line.strip()]
            elif current_cve and line.strip():
                cve_details.append(line.strip())
        
        # Add the last CVE if exists
        if current_cve:
            details_text = '\n'.join(cve_details)
            cvss, severity = extract_severity(details_text)
            cve_findings.append({
                'id': current_cve,
                'details': details_text,
                'url': get_cve_url(current_cve),
                'cvss': cvss,
                'severity': severity,
                'port': port,
                'target': target
            })
            if verbose:
                sev_str = f" [{severity}" + (f", CVSS: {cvss}" if cvss else "") + "]"
                print(f"[+] Found vulnerability: {current_cve}{sev_str}")
        
        # Log results
        if cve_findings:
            if verbose:
                print(f"[+] Total {len(cve_findings)} vulnerabilities found on {target}:{port}")
        else:
            if verbose:
                print(f"[*] No vulnerabilities found on {target}:{port}")
            
    except subprocess.TimeoutExpired:
        if verbose:
            print(f"[!] Vulnerability scan timed out for {target}:{port}")
    except Exception as e:
        if verbose:
            print(f"[!] Error checking vulnerabilities for {target}:{port}: {str(e)}")
    
    return cve_findings

def scan_domain_for_vulnerabilities(domain, ports=None, scan_all_ports=False, verbose=True):
    """Scan a domain for vulnerabilities."""
    # Check if the host is up
    if not ping_host(domain, verbose):
        if verbose:
            print(f"[!] Skipping {domain} as it appears to be down")
        return {
            'domain': domain,
            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'is_up': False,
            'ports': {},
            'vulnerabilities': []
        }
    
    # Resolve domain to IP for reporting purposes
    ip = None
    try:
        ip = socket.gethostbyname(domain)
    except:
        if verbose:
            print(f"[!] Could not resolve {domain} to IP address")
    
    result = {
        'domain': domain,
        'ip': ip,
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'is_up': True,
        'ports': {},
        'vulnerabilities': []
    }
    
    # First, discover open ports if not provided
    if not ports or scan_all_ports:
        if verbose:
            print(f"[*] Discovering open ports on {domain}...")
        
        try:
            port_scan_cmd = ['nmap', '-sV', '--open', domain]
            if verbose:
                print(f"[*] Running: {' '.join(port_scan_cmd)}")
                
            port_scan = subprocess.run(port_scan_cmd, capture_output=True, text=True, timeout=180)
            
            # Extract open ports from nmap output
            discovered_ports = []
            for line in port_scan.stdout.splitlines():
                if '/tcp' in line or '/udp' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        port_info = parts[0]
                        port = port_info.split('/')[0]
                        discovered_ports.append(port)
                        
                        # Store port info in result
                        result['ports'][port] = {
                            'protocol': port_info.split('/')[1],
                            'service': ' '.join(parts[2:]) if len(parts) > 2 else "Unknown",
                            'vulnerabilities': []
                        }
            
            if verbose:
                print(f"[+] Discovered {len(discovered_ports)} open ports on {domain}: {', '.join(discovered_ports)}")
                
            ports = discovered_ports
        except Exception as e:
            if verbose:
                print(f"[!] Error discovering ports on {domain}: {str(e)}")
            if not ports:  # If no ports were provided and discovery failed
                return result
    
    # Now scan each port for vulnerabilities
    total_vulns = 0
    for port in ports:
        if verbose:
            print(f"\n[*] Scanning port {port} on {domain} for vulnerabilities...")
            
        # Pass the domain directly to the vulnerability scanner, not the IP
        vulnerabilities = scan_port_for_vulnerabilities(domain, port, verbose)
        
        if port not in result['ports']:
            result['ports'][port] = {
                'protocol': 'tcp',  # Default to TCP
                'service': "Unknown",
                'vulnerabilities': []
            }
        
        result['ports'][port]['vulnerabilities'] = vulnerabilities
        result['vulnerabilities'].extend(vulnerabilities)
        total_vulns += len(vulnerabilities)
    
    if verbose:
        print(f"\n[+] Completed vulnerability scan for {domain}")
        print(f"[+] Found {total_vulns} vulnerabilities across {len(ports)} ports")
    
    return result

def ping_host(host, verbose=True):
    """Check if a host is up using ping."""
    try:
        if verbose:
            print(f"[*] Pinging {host}...")
            
        # Use the appropriate ping command based on the OS
        if os.name == 'nt':  # Windows
            param = '-n'
        else:  # Unix/Linux/MacOS
            param = '-c'
            
        # Run ping command with a timeout
        ping_cmd = ['ping', param, '1', host]
        result = subprocess.run(ping_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5)
        
        # Check if ping was successful
        if result.returncode == 0:
            if verbose:
                print(f"[+] Host {host} is up")
            return True
        else:
            if verbose:
                print(f"[!] Host {host} appears to be down")
            return False
    except subprocess.TimeoutExpired:
        if verbose:
            print(f"[!] Ping timed out for {host}")
        return False
    except Exception as e:
        if verbose:
            print(f"[!] Error pinging {host}: {str(e)}")
        return False

def ping_sweep(domains, verbose=True):
    """
    Perform a ping sweep of all domains and return only the reachable ones.
    """
    reachable_domains = []
    unreachable_domains = []
    
    if verbose:
        print(f"[*] Starting initial ping sweep of {len(domains)} domains...")
    
    for i, domain in enumerate(domains, 1):
        if verbose and i % 10 == 0:
            print(f"[*] Ping progress: {i}/{len(domains)} domains checked")
            
        if ping_host(domain, verbose=False):  # Use quieter ping
            reachable_domains.append(domain)
        else:
            unreachable_domains.append(domain)
    
    if verbose:
        print(f"[+] Ping sweep complete: {len(reachable_domains)} domains reachable, {len(unreachable_domains)} unreachable")
        
    return reachable_domains, unreachable_domains

def read_domains_from_json(json_file):
    """Read domains and subdomains from the all_subdomains.json file."""
    domains = []
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
            
        for item in data:
            # Add main domain
            if 'domain' in item and item['domain']:
                domains.append(item['domain'])
            
            # Add subdomains
            if 'results' in item:
                for subdomain_info in item['results']:
                    if 'subdomain' in subdomain_info and subdomain_info['subdomain'] and subdomain_info['subdomain'] != "No names were discovered":
                        domains.append(subdomain_info['subdomain'])
    except Exception as e:
        print(f"[!] Error reading domains from {json_file}: {str(e)}")
    
    return list(set(domains))  # Remove duplicates

def save_results_to_json(results, output_file):
    """Save scan results to a JSON file."""
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"[+] Results saved to {output_file}")
    except Exception as e:
        print(f"[!] Error saving results: {str(e)}")

def generate_summary_report(results, output_file):
    """Generate a human-readable summary report from scan results."""
    try:
        with open(output_file, 'w') as f:
            f.write("CVE VULNERABILITY SCAN REPORT\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Count vulnerabilities by severity
            severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Unknown": 0}
            all_cves = set()
            domains_up = 0
            domains_with_vulns = 0
            
            for result in results:
                domain = result['domain']
                if result['is_up']:
                    domains_up += 1
                    
                    if len(result['vulnerabilities']) > 0:
                        domains_with_vulns += 1
                    
                    for vuln in result['vulnerabilities']:
                        severity = vuln['severity']
                        severity_counts[severity] += 1
                        all_cves.add(vuln['id'])
            
            # Write summary statistics
            f.write("SUMMARY STATISTICS\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total domains scanned: {len(results)}\n")
            f.write(f"Domains reachable: {domains_up}\n")
            f.write(f"Domains with vulnerabilities: {domains_with_vulns}\n")
            f.write(f"Total unique CVEs found: {len(all_cves)}\n")
            f.write(f"Vulnerability severity breakdown:\n")
            for severity, count in severity_counts.items():
                f.write(f"  - {severity}: {count}\n")
            f.write("\n")
            
            # Write detailed findings for each domain
            f.write("DETAILED FINDINGS\n")
            f.write("-" * 80 + "\n")
            
            for result in results:
                domain = result['domain']
                ip_info = f" (IP: {result['ip']})" if result['ip'] else ""
                
                f.write(f"\nDomain: {domain}{ip_info}\n")
                f.write("=" * 40 + "\n")
                f.write(f"Scan time: {result['timestamp']}\n")
                
                if not result['is_up']:
                    f.write("Status: Domain unreachable (down or does not exist)\n")
                    continue
                    
                if not result['vulnerabilities']:
                    f.write("No vulnerabilities found.\n")
                    continue
                
                f.write(f"Vulnerabilities found: {len(result['vulnerabilities'])}\n\n")
                
                # Group vulnerabilities by port
                for port, port_info in result['ports'].items():
                    vulns = port_info['vulnerabilities']
                    if not vulns:
                        continue
                        
                    f.write(f"Port {port} ({port_info['service']}):\n")
                    f.write("-" * 40 + "\n")
                    
                    for vuln in vulns:
                        cvss_info = f" (CVSS: {vuln['cvss']})" if vuln['cvss'] else ""
                        f.write(f"  {vuln['id']} - {vuln['severity']}{cvss_info}\n")
                        f.write(f"  URL: {vuln['url']}\n")
                        f.write(f"  Details:\n")
                        
                        for detail_line in vuln['details'].splitlines():
                            f.write(f"    {detail_line}\n")
                        f.write("\n")
                
                f.write("\n")
            
            f.write("-" * 80 + "\n")
            f.write("End of Report\n")
        
        print(f"[+] Summary report saved to {output_file}")
    except Exception as e:
        print(f"[!] Error generating summary report: {str(e)}")

def load_domains_from_file(file_path):
    """Load domains from a text file, one domain per line."""
    try:
        with open(file_path, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
        return list(set(domains))  # Remove duplicates
    except Exception as e:
        print(f"[!] Error loading domains from {file_path}: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description='Enhanced CVE Scanner')
    parser.add_argument('--input-json', help='Input JSON file containing domains')
    parser.add_argument('--input', help='Input text file containing domains (one per line)')
    parser.add_argument('--output-json', help='Output JSON file for results')
    parser.add_argument('--output-report', help='Output text file for report')
    parser.add_argument('--ports', help='Comma-separated list of ports to scan')
    parser.add_argument('--discover-ports', action='store_true', help='Discover open ports automatically')
    parser.add_argument('--max-targets', type=int, help='Maximum number of targets to scan')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--skip-ping', action='store_true', help='Skip initial ping check')
    args = parser.parse_args()
    
    # Load domains from input file
    domains = []
    if args.input_json:
        domains = read_domains_from_json(args.input_json)
    elif args.input:
        domains = load_domains_from_file(args.input)
    else:
        print("Error: No input file specified")
        sys.exit(1)
    
    if not domains:
        print("Error: No domains found in input file")
        sys.exit(1)
    
    # Limit number of targets if specified
    if args.max_targets and len(domains) > args.max_targets:
        print(f"[*] Limiting scan to {args.max_targets} targets")
        domains = domains[:args.max_targets]
    
    # First, check which targets are reachable
    print("\n[*] Checking which targets are reachable...")
    reachable_domains = []
    for domain in domains:
        if args.skip_ping or ping_host(domain, args.verbose):
            reachable_domains.append(domain)
            if args.verbose:
                print(f"[+] {domain} is reachable")
        else:
            if args.verbose:
                print(f"[!] {domain} is not reachable, skipping")
    
    print(f"\n[*] Found {len(reachable_domains)} reachable targets out of {len(domains)} total targets")
    
    if not reachable_domains:
        print("[!] No reachable targets found, exiting")
        sys.exit(1)
    
    # Parse ports if specified
    ports = None
    if args.ports:
        ports = [p.strip() for p in args.ports.split(',')]
    
    # Scan each reachable domain
    results = []
    for i, domain in enumerate(reachable_domains, 1):
        print(f"\n[*] Scanning domain {i}/{len(reachable_domains)}: {domain}")
        result = scan_domain_for_vulnerabilities(
            domain,
            ports=ports,
            scan_all_ports=args.discover_ports,
            verbose=args.verbose
        )
        results.append(result)
    
    # Save results
    if args.output_json:
        save_results_to_json(results, args.output_json)
        print(f"\n[+] Results saved to {args.output_json}")
    
    if args.output_report:
        generate_summary_report(results, args.output_report)
        print(f"[+] Report generated at {args.output_report}")
    
    # Print summary
    total_vulns = sum(len(r['vulnerabilities']) for r in results)
    print(f"\n[*] Scan complete!")
    print(f"    - Scanned {len(reachable_domains)} reachable domains")
    print(f"    - Found {total_vulns} vulnerabilities")
    
    return 0

if __name__ == "__main__":
    main()