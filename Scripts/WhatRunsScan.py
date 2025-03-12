#!/usr/bin/env python3
# filepath: /home/s141422/SecurityProject/EASM-Bunyamin-Siebe/Scripts/WhatRunsScan.py

import csv
import subprocess
import os
import json
import time
import re
from datetime import datetime

def scan_ports_and_services(ip, verbose=True):
    """
    Scan an IP address for open ports and identify running services.
    Returns a dictionary with port information and service details.
    """
    results = {
        'ip': ip,
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'ports': {}
    }
    
    if verbose:
        print(f"\n[*] Scanning ports and services on {ip}...")
    
    try:
        # Run nmap with service detection
        command = ['nmap', '-sV', '-p-', '--open', '--reason', ip]
        if verbose:
            print(f"[*] Executing: {' '.join(command)}")
            
        nmap_process = subprocess.run(command, capture_output=True, text=True, timeout=300)
        
        if nmap_process.returncode != 0:
            if verbose:
                print(f"[!] Error scanning {ip}: {nmap_process.stderr}")
            return results
            
        # Parse nmap output to get ports and services
        for line in nmap_process.stdout.splitlines():
            if '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = parts[0]
                    state = parts[1]
                    service = ' '.join(parts[2:])
                    
                    # Extract port number and protocol
                    port, protocol = port_info.split('/')
                    
                    # Store port information
                    results['ports'][port] = {
                        'protocol': protocol,
                        'state': state,
                        'service': service,
                        'vulnerabilities': []
                    }
                    
                    if verbose:
                        print(f"[+] Found: Port {port}/{protocol} is {state} - {service}")
        
        # For each open port, check for vulnerabilities
        port_count = len(results['ports'])
        if port_count > 0:
            if verbose:
                print(f"[*] Found {port_count} open ports on {ip}")
                print(f"[*] Checking for vulnerabilities...")
            
            for port in results['ports']:
                if verbose:
                    print(f"[*] Checking vulnerabilities on port {port}...")
                check_vulnerabilities(ip, port, results, verbose)
        else:
            if verbose:
                print(f"[*] No open ports found on {ip}")
            
    except subprocess.TimeoutExpired:
        if verbose:
            print(f"[!] Scan timed out for {ip}")
    except Exception as e:
        if verbose:
            print(f"[!] Error during scan of {ip}: {str(e)}")
    
    # Print summary of findings
    print_ip_summary(results)
    
    return results

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

def check_vulnerabilities(ip, port, results, verbose=True):
    """Check if services running on a specific port have known vulnerabilities."""
    try:
        # Run vulnerability scan for the specific port
        command = ['nmap', '--script', 'vuln', '-p', port, ip]
        if verbose:
            print(f"[*] Running: {' '.join(command)}")
            
        vuln_process = subprocess.run(command, capture_output=True, text=True, timeout=180)
        
        if vuln_process.returncode != 0:
            if verbose:
                print(f"[!] Vulnerability scan failed for {ip}:{port}")
            return
        
        vuln_output = vuln_process.stdout
        
        # Look for CVE identifiers
        cve_findings = []
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
                        'severity': severity
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
                'severity': severity
            })
            if verbose:
                sev_str = f" [{severity}" + (f", CVSS: {cvss}" if cvss else "") + "]"
                print(f"[+] Found vulnerability: {current_cve}{sev_str}")
        
        # Add vulnerabilities to the results
        if cve_findings:
            results['ports'][port]['vulnerabilities'] = cve_findings
            if verbose:
                print(f"[+] Total {len(cve_findings)} vulnerabilities found on port {port}")
        else:
            if verbose:
                print(f"[*] No vulnerabilities found on port {port}")
            
    except subprocess.TimeoutExpired:
        if verbose:
            print(f"[!] Vulnerability scan timed out for {ip}:{port}")
    except Exception as e:
        if verbose:
            print(f"[!] Error checking vulnerabilities for {ip}:{port}: {str(e)}")

def print_ip_summary(result):
    """Print a summary of findings for an IP address."""
    ip = result['ip']
    port_count = len(result['ports'])
    
    print(f"\n{'='*60}")
    print(f"SUMMARY FOR IP: {ip}")
    print(f"{'='*60}")
    print(f"Scan completed at: {result['timestamp']}")
    print(f"Open ports found: {port_count}")
    
    if port_count > 0:
        print("\nPORT DETAILS:")
        print(f"{'-'*50}")
        
        total_vulns = 0
        for port, info in result['ports'].items():
            vuln_count = len(info['vulnerabilities'])
            total_vulns += vuln_count
            
            vuln_text = f"({vuln_count} vulnerabilities)" if vuln_count > 0 else "(No vulnerabilities)"
            print(f"Port {port}/{info['protocol']}: {info['service']} {vuln_text}")
            
            # Show vulnerability IDs if any found
            if vuln_count > 0:
                for vuln in info['vulnerabilities']:
                    severity_str = f" - {vuln['severity']}"
                    if vuln['cvss']:
                        severity_str += f" (CVSS: {vuln['cvss']})"
                    print(f"  - {vuln['id']}{severity_str}")
                    print(f"    URL: {vuln['url']}")
        
        print(f"\nTotal vulnerabilities found: {total_vulns}")
    
    print(f"{'='*60}\n")

def read_ips_from_csv(csv_file):
    """Read IPv4 addresses from the CSV file."""
    ips = []
    try:
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if 'IPv4' in row and row['IPv4'] != 'Unresolved':
                    ip = row['IPv4']
                    if ip and ip.strip():
                        ips.append(ip.strip())
    except FileNotFoundError:
        print(f"[!] CSV file not found: {csv_file}")
    return list(set(ips))  # Remove duplicates

def write_results_to_file(results_list, output_file, format='txt'):
    """Write scan results to output file in specified format."""
    if format == 'json':
        with open(output_file, 'w') as f:
            json.dump(results_list, f, indent=4)
    else:  # Default to text format
        with open(output_file, 'w') as f:
            f.write("PORT SCANNING AND SERVICE DETECTION RESULTS\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            for result in results_list:
                f.write(f"IP Address: {result['ip']}\n")
                f.write(f"Scan Time: {result['timestamp']}\n")
                f.write("-" * 80 + "\n")
                
                if not result['ports']:
                    f.write("No open ports found.\n\n")
                    continue
                
                f.write("PORT      PROTOCOL  STATE   SERVICE                  VULNERABILITIES\n")
                f.write("-" * 80 + "\n")
                
                for port, info in result['ports'].items():
                    vuln_count = len(info['vulnerabilities'])
                    vuln_text = f"({vuln_count} found)" if vuln_count > 0 else "None"
                    
                    f.write(f"{port:<10}{info['protocol']:<10}{info['state']:<8}{info['service']:<25}{vuln_text}\n")
                    
                    # List vulnerabilities if found
                    if vuln_count > 0:
                        f.write("\n    VULNERABILITIES:\n")
                        for vuln in info['vulnerabilities']:
                            severity_str = f" - {vuln['severity']}"
                            if vuln['cvss']:
                                severity_str += f" (CVSS: {vuln['cvss']})"
                            
                            f.write(f"    * {vuln['id']}{severity_str}\n")
                            f.write(f"      URL: {vuln['url']}\n")
                            for detail in vuln['details'].split('\n'):
                                f.write(f"      {detail}\n")
                        f.write("\n")
                
                f.write("\n" + "=" * 80 + "\n\n")

def write_incremental_log(result, log_file):
    """Write scan results for an IP incrementally to avoid data loss."""
    with open(log_file, 'a') as f:
        f.write(f"\nIP Address: {result['ip']}\n")
        f.write(f"Scan Time: {result['timestamp']}\n")
        f.write("-" * 80 + "\n")
        
        if not result['ports']:
            f.write("No open ports found.\n\n")
            return
        
        f.write("PORT      PROTOCOL  STATE   SERVICE                  VULNERABILITIES\n")
        f.write("-" * 80 + "\n")
        
        for port, info in result['ports'].items():
            vuln_count = len(info['vulnerabilities'])
            vuln_text = f"({vuln_count} found)" if vuln_count > 0 else "None"
            
            f.write(f"{port:<10}{info['protocol']:<10}{info['state']:<8}{info['service']:<25}{vuln_text}\n")
            
            # List vulnerabilities if found
            if vuln_count > 0:
                f.write("\n    VULNERABILITIES:\n")
                for vuln in info['vulnerabilities']:
                    severity_str = f" - {vuln['severity']}"
                    if vuln['cvss']:
                        severity_str += f" (CVSS: {vuln['cvss']})"
                    
                    f.write(f"    * {vuln['id']}{severity_str}\n")
                    f.write(f"      URL: {vuln['url']}\n")
                    for detail in vuln['details'].split('\n'):
                        f.write(f"      {detail}\n")
                f.write("\n")
        
        f.write("\n" + "=" * 80 + "\n")

def main():
    # Define file paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(script_dir)
    input_file = os.path.join(base_dir, "foundData", "subdomains_with_ips.csv")
    output_dir = os.path.join(base_dir, "foundData")
    output_file = os.path.join(output_dir, "port_services_scan.txt")
    json_output = os.path.join(output_dir, "port_services_scan.json")
    log_file = os.path.join(output_dir, "scan_log.txt")

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Initialize log file
    with open(log_file, 'w') as f:
        f.write(f"PORT SCANNING LOG - Started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")

    # Read IPs from CSV
    print("[*] Reading IP addresses from CSV...")
    ips = read_ips_from_csv(input_file)
    
    if not ips:
        print("[!] No valid IP addresses found in the CSV file.")
        return

    # Scan each IP and store results
    print(f"[*] Starting port and service scan for {len(ips)} IP addresses...")
    results_list = []
    
    for i, ip in enumerate(ips, 1):
        print(f"\n[*] Scanning IP {i}/{len(ips)}: {ip}...")
        scan_result = scan_ports_and_services(ip)
        results_list.append(scan_result)
        
        # Write incremental log to avoid losing data if script crashes
        write_incremental_log(scan_result, log_file)
        
        # Short pause between scans to be nice to the network
        if i < len(ips):
            print(f"[*] Pausing before next scan...")
            time.sleep(2)

    # Write final results to files
    print("\n[*] Writing final results to files...")
    write_results_to_file(results_list, output_file, format='txt')
    write_results_to_file(results_list, json_output, format='json')
    
    print(f"[+] Scan complete. Results saved to:")
    print(f"    - {output_file}")
    print(f"    - {json_output}")
    print(f"    - {log_file} (incremental log)")

if __name__ == "__main__":
    main()