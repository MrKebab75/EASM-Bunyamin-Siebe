#!/usr/bin/env python3
# filepath: /home/s141422/SecurityProject/EASM-Bunyamin-Siebe/Scripts/WhatRunsScan.py

import csv
import subprocess
import os
import json
import time
import re
import urllib.parse
import ast
import socket
from datetime import datetime
import requests
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
WHATRUNS_ENABLED = True

# Try to import webtech, with fallback if not available
try:
    import webtech
    WEBTECH_AVAILABLE = True
    print("[+] webtech module found. Web technology detection is enabled.")
except ImportError:
    WEBTECH_AVAILABLE = False
    print("[!] webtech module not found. Web technology detection will be limited.")
    print("[!] Run this script in a virtual environment with webtech installed:")
    print("    python3 -m venv myvenv")
    print("    source myvenv/bin/activate")
    print("    pip install webtech requests")

def detect_technologies_with_whatruns(domain, timeout=10, verbose=True):
    """
    Detect technologies using WhatRuns API.
    """
    technologies = []
    
    if verbose:
        print(f"[*] Querying WhatRuns API for {domain}...")
    
    try:
        # Use the exact same request format as your working test.py
        url = "https://www.whatruns.com/api/v1/get_site_apps"
        data = {
            "data": {
                "hostname": domain,
                "url": domain,
                "rawhostname": domain
            }
        }
        
        # Use the exact same encoding method that works in test.py
        data = urllib.parse.urlencode({k: json.dumps(v) for k, v in data.items()})
        data = data.replace('+', '')
        
        # Use the same simpler headers that work in test.py
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        
        if verbose:
            print(f"[*] Sending request to WhatRuns API...")
            
        response = requests.post(url, data=data, headers=headers, timeout=timeout)
        
        if response.status_code != 200:
            if verbose:
                print(f"[!] WhatRuns API returned status {response.status_code}")
            return technologies
        
        if verbose:
            print(f"[*] Received response, processing data...")
            
        # Parse response following the exact steps from test.py
        loaded = json.loads(response.content)
        
        # Debug output
        if verbose:
            print(f"[*] Response keys: {list(loaded.keys())}")
        
        if 'apps' not in loaded:
            if verbose:
                print(f"[!] WhatRuns API response doesn't contain 'apps' key")
                print(f"[*] Response preview: {str(loaded)[:100]}...")
            return technologies
        
        # Use the same ast.literal_eval that works in test.py
        apps = ast.literal_eval(loaded['apps'])
        
        # Use the same list conversion that works in test.py
        nuance = list(apps.keys())[0]  # Python 3 compatible
        
        # Process technologies exactly as in test.py
        for app_type, values in apps[nuance].items():
            for item in values:
                dt = datetime.fromtimestamp(item['detectedTime'] / 1000)
                ldt = datetime.fromtimestamp(item['latestDetectedTime'] / 1000)
                
                technologies.append({
                    'name': item['name'],
                    'version': item.get('version', 'Unknown'),
                    'categories': [app_type],
                    'confidence': 90,
                    'detected_time': dt.strftime('%Y-%m-%d'),
                    'latest_detected': ldt.strftime('%Y-%m-%d')
                })
                
                if verbose:
                    print(f"[+] WhatRuns detected: {item['name']} ({app_type})")
        
        if verbose:
            print(f"[+] WhatRuns found {len(technologies)} technologies")
            
    except Exception as e:
        if verbose:
            print(f"[!] Error using WhatRuns API: {str(e)}")
            
    return technologies

def parse_service_version(service_string):
    """Extract service name and version from nmap service detection string."""
    # Common patterns in nmap service detection
    service_name = service_string.split()[0] if service_string else "Unknown"
    version = "Unknown"
    
    # Extract version information using common patterns
    if " " in service_string:
        parts = service_string.split()
        # Look for version patterns like "apache/2.4.41" or "nginx 1.18.0"
        for part in parts:
            if "/" in part:
                name_ver = part.split("/")
                if len(name_ver) == 2 and any(c.isdigit() for c in name_ver[1]):
                    service_name = name_ver[0]
                    version = name_ver[1]
                    break
            # Match patterns like "1.2.3" or "v1.2.3"
            elif part.startswith("v") and part[1:].replace(".", "").isdigit():
                version = part[1:]  # Remove 'v' prefix
                break
            elif part.replace(".", "").isdigit():
                version = part
                break
    
    return service_name, version

def check_for_web_service(service):
    """Check if a service is likely to be a web service."""
    web_services = ['http', 'https', 'nginx', 'apache', 'iis', 'webserver', 'web']
    service_lower = service.lower()
    return any(web_service in service_lower for web_service in web_services)

def detect_web_technologies(ip, port, protocol="http", domains=None, timeout=10, verbose=True):
    """
    Detect web technologies running on a web server.
    If domains are provided, they'll be used for WhatRuns API detection.
    """
    technologies = []
    domains = domains or []
    url = f"{protocol}://{ip}:{port}"
    
    if verbose:
        print(f"[*] Detecting web technologies on {url}")
    
    # Try to get basic server information from headers first
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        }
        response = requests.get(url, timeout=timeout, verify=False, headers=headers)
        
        # Extract version from server header if available
        server = response.headers.get('Server', '')
        if server:
            # Try to extract version from server header
            server_parts = server.split('/')
            server_name = server_parts[0]
            server_version = server_parts[1] if len(server_parts) > 1 else 'Unknown'
            
            technologies.append({
                'name': server_name,
                'version': server_version,
                'categories': ['Web Server'],
                'confidence': 90
            })
            
            if verbose:
                print(f"[+] Detected from headers: {server_name} {server_version}")
                
        # Check for common technology indicators in headers
        for header, value in response.headers.items():
            if header.lower() == 'x-powered-by':
                # Try to extract technology and version (e.g., "PHP/7.4.3")
                parts = value.split('/')
                tech_name = parts[0]
                tech_version = parts[1] if len(parts) > 1 else 'Unknown'
                
                technologies.append({
                    'name': tech_name,
                    'version': tech_version,
                    'categories': ['Web Framework'],
                    'confidence': 90
                })
                if verbose:
                    print(f"[+] Detected technology: {tech_name} {tech_version}")
    except requests.RequestException as e:
        if verbose:
            print(f"[!] Error making request to {url}: {str(e)}")
        
    if WEBTECH_AVAILABLE:
        # Use webtech library if available
        try:
            wt = webtech.WebTech(options={'silent': True, 'timeout': timeout})
            
            # Wrap this part in a try-except to handle different return formats
            try:
                results = wt.start_from_url(url)
                
                # Check if we got a dictionary (as expected) or something else
                if hasattr(results, 'tech'):
                    # Object with tech attribute
                    techs = results.tech
                elif isinstance(results, dict) and 'tech' in results:
                    # Dictionary with tech key
                    techs = results.get('tech', [])
                elif isinstance(results, list):
                    # List of technologies
                    techs = results
                else:
                    # Unknown format
                    if verbose:
                        print(f"[!] Unexpected result format from webtech: {type(results)}")
                    techs = []
                    
                # Process the technologies
                for tech in techs:
                    if isinstance(tech, dict):
                        # Check if we already detected this technology from headers
                        tech_name = tech.get('name', 'Unknown')
                        if not any(t['name'].lower() == tech_name.lower() for t in technologies):
                            technologies.append({
                                'name': tech_name,
                                'version': tech.get('version', 'Unknown'),
                                'categories': tech.get('categories', []),
                                'confidence': tech.get('confidence', 0)
                            })
            except AttributeError:
                # Handle the case where results is a string or other non-dict type
                if verbose:
                    print(f"[!] Could not process webtech results: unexpected format")
            
            if verbose and technologies:
                print(f"[+] Found {len(technologies)} technologies on {url}:")
                for tech in technologies:
                    print(f"    - {tech['name']} {tech['version']} ({', '.join(tech['categories'])})")
            elif verbose:
                print(f"[*] No technologies detected on {url}")
                
        except Exception as e:
            if verbose:
                print(f"[!] Error detecting web technologies on {url}: {str(e)}")
    else:
        # Fallback to basic content analysis if webtech is not available
        try:
            response_text = response.text.lower()
            
            # Simple technology fingerprints
            fingerprints = {
                'wordpress': {'pattern': 'wp-content|wp-includes', 'version_pattern': r'ver=([0-9.]+)', 'categories': ['CMS']},
                'jquery': {'pattern': 'jquery', 'version_pattern': r'jquery[.-]([0-9.]+)', 'categories': ['JavaScript Library']},
                'bootstrap': {'pattern': 'bootstrap', 'version_pattern': r'bootstrap[.-]([0-9.]+)', 'categories': ['CSS Framework']},
                'php': {'pattern': 'php', 'version_pattern': r'php/([0-9.]+)', 'categories': ['Programming Language']},
                'nginx': {'pattern': 'nginx', 'version_pattern': r'nginx/([0-9.]+)', 'categories': ['Web Server']},
                'apache': {'pattern': 'apache', 'version_pattern': r'apache/([0-9.]+)', 'categories': ['Web Server']}
            }
            
            for tech_name, tech_data in fingerprints.items():
                if re.search(tech_data['pattern'], response_text):
                    # Look for version
                    version = 'Unknown'
                    version_match = re.search(tech_data['version_pattern'], response_text)
                    if version_match:
                        version = version_match.group(1)
                        
                    # Check if we already detected this technology
                    if not any(t['name'].lower() == tech_name for t in technologies):
                        technologies.append({
                            'name': tech_name.capitalize(),
                            'version': version,
                            'categories': tech_data['categories'],
                            'confidence': 70
                        })
                        if verbose:
                            print(f"[+] Detected technology: {tech_name.capitalize()} {version}")
                        
        except Exception as e:
            if verbose:
                print(f"[!] Error in fallback technology detection on {url}: {str(e)}")
    
    # Add WhatRuns detection using domain names from CSV
    if WHATRUNS_ENABLED and domains:
        for domain in domains:
            if verbose:
                print(f"[*] Using WhatRuns API for domain: {domain}")
                
            try:
                whatruns_techs = detect_technologies_with_whatruns(domain, timeout, verbose)
                
                # Add unique technologies from WhatRuns
                for tech in whatruns_techs:
                    if not any(t['name'].lower() == tech['name'].lower() for t in technologies):
                        technologies.append(tech)
                        if verbose and tech['name'] != 'Unknown':
                            print(f"[+] WhatRuns added: {tech['name']} {tech['version']}")
            except Exception as e:
                if verbose:
                    print(f"[!] Error using WhatRuns for domain {domain}: {str(e)}")
    
    return technologies

def scan_ports_and_services(ip, domains=None, verbose=True):
    """
    Scan an IP address for open ports and identify running services.
    Returns a dictionary with port information and service details.
    """
    domains = domains or []  # Default to empty list if None
    
    results = {
        'ip': ip,
        'domains': domains,
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'ports': {}
    }
    
    if verbose:
        domain_str = f" ({', '.join(domains)})" if domains else ""
        print(f"\n[*] Scanning ports and services on {ip}{domain_str}...")
    
    # Run nmap scan as before
    try:
        # Run nmap with service detection
        command = ['nmap', '-sV', '-p-', '--open', '--reason', ip]
        if verbose:
            print(f"[*] Executing: {' '.join(command)}")
            
        nmap_process = subprocess.run(command, capture_output=True, text=True, timeout=300)
        
        if nmap_process.returncode != 0:
            if verbose:
                print(f"[!] Error scanning {ip}: {nmap_process.stderr}")
            # Don't return here, continue to WhatRuns check if domains are available
        else:
            # Process nmap results as before
            for line in nmap_process.stdout.splitlines():
                if '/tcp' in line or '/udp' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        port_info = parts[0]
                        state = parts[1]
                        service_str = ' '.join(parts[2:])
                        
                        # Extract port number and protocol
                        port, protocol = port_info.split('/')
                        
                        # Parse service and version information
                        service_name, service_version = parse_service_version(service_str)
                        
                        # Store port information
                        results['ports'][port] = {
                            'protocol': protocol,
                            'state': state,
                            'service': service_str,
                            'service_name': service_name,
                            'service_version': service_version,
                            'vulnerabilities': [],
                            'technologies': []  # Initialize technologies list
                        }
                        
                        if verbose:
                            version_info = f" (version: {service_version})" if service_version != "Unknown" else ""
                            print(f"[+] Found: Port {port}/{protocol} is {state} - {service_name}{version_info}")

            # After finding all open ports, probe each one for web services
            web_ports = []
            all_ports = list(results['ports'].keys())

            if verbose:
                print(f"[*] Checking all {len(all_ports)} open ports for web services...")

            # First, add ports with obvious web services based on nmap detection
            for port, info in results['ports'].items():
                if check_for_web_service(info['service']) or port in ['80', '443', '8080', '8443', '8000', '8008', '3000']:
                    web_ports.append((port, 'https' if port == '443' or port == '8443' else 'http'))

            # Then, probe all remaining ports with HTTP requests to check if they respond like web servers
            remaining_ports = [p for p in all_ports if not any(p == wp[0] for wp in web_ports)]
            if remaining_ports:
                if verbose:
                    print(f"[*] Probing {len(remaining_ports)} additional ports for hidden web services...")
                
                for port in remaining_ports:
                    # Try HTTPS first, then fallback to HTTP
                    for protocol in ['https', 'http']:
                        try:
                            url = f"{protocol}://{ip}:{port}"
                            response = requests.get(url, timeout=3, verify=False, allow_redirects=False)
                            
                            # Check if it looks like a web response
                            if response.status_code and (
                                'html' in response.headers.get('Content-Type', '').lower() or 
                                '<html' in response.text.lower()[:500] or
                                'server' in response.headers or
                                'set-cookie' in response.headers
                            ):
                                web_ports.append((port, protocol))
                                if verbose:
                                    print(f"[+] Discovered hidden web service on {url}")
                                break  # No need to try HTTP if HTTPS worked
                        except requests.exceptions.RequestException:
                            continue  # Try next protocol or port
            
            # For web ports, detect technologies
            if web_ports:
                if verbose:
                    print(f"[*] Checking for web technologies on {len(web_ports)} potential web ports...")
                    
                for port, protocol in web_ports:
                    technologies = detect_web_technologies(ip, port, protocol, domains=domains, verbose=verbose)
                    results['ports'][port]['technologies'] = technologies
            
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
    
    # Check if we have any domains and should run WhatRuns API regardless of open ports
    if WHATRUNS_ENABLED and domains:
        whatruns_technologies_found = False
        
        if verbose:
            print(f"[*] No open ports found with nmap, but domains are available.")
            print(f"[*] Checking WhatRuns API for domain technologies...")
        
        for domain in domains:
            if verbose:
                print(f"[*] Querying WhatRuns API for domain: {domain}")
                
            try:
                whatruns_techs = detect_technologies_with_whatruns(domain, timeout=10, verbose=verbose)
                
                if whatruns_techs:
                    # If WhatRuns found technologies but nmap found no open ports,
                    # create a special "web" port entry to show the technologies
                    if not results['ports']:
                        results['ports']['80'] = {
                            'protocol': 'tcp',
                            'state': 'filtered',  # We don't know the actual state
                            'service': 'http',
                            'service_name': 'http',
                            'service_version': 'Unknown',
                            'vulnerabilities': [],
                            'technologies': whatruns_techs
                        }
                        whatruns_technologies_found = True
                        
                        if verbose:
                            print(f"[+] Found {len(whatruns_techs)} technologies through WhatRuns API for {domain}")
                    
            except Exception as e:
                if verbose:
                    print(f"[!] Error using WhatRuns for domain {domain}: {str(e)}")
        
        if whatruns_technologies_found:
            if verbose:
                print(f"[*] Added technologies from WhatRuns API to results")
    
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
        total_techs = 0
        
        for port, info in result['ports'].items():
            vuln_count = len(info['vulnerabilities'])
            tech_count = len(info['technologies'])
            total_vulns += vuln_count
            total_techs += tech_count
            
            status_text = []
            if tech_count > 0:
                status_text.append(f"{tech_count} technologies")
            if vuln_count > 0:
                status_text.append(f"{vuln_count} vulnerabilities")
            
            status = f" ({', '.join(status_text)})" if status_text else ""
            
            version_info = f" {info['service_version']}" if info['service_version'] != "Unknown" else ""
            print(f"Port {port}/{info['protocol']}: {info['service_name']}{version_info}{status}")
            
            # Show detected technologies
            if tech_count > 0:
                print("  Technologies:")
                for tech in info['technologies']:
                    version = f" {tech['version']}" if tech['version'] != 'Unknown' else ""
                    categories = ', '.join(tech['categories']) if tech['categories'] else 'Unknown'
                    print(f"    - {tech['name']}{version} ({categories})")
            
            # Show vulnerability IDs if any found
            if vuln_count > 0:
                print("  Vulnerabilities:")
                for vuln in info['vulnerabilities']:
                    severity_str = f" - {vuln['severity']}"
                    if vuln['cvss']:
                        severity_str += f" (CVSS: {vuln['cvss']})"
                    print(f"    - {vuln['id']}{severity_str}")
                    print(f"      URL: {vuln['url']}")
        
        print(f"\nTotal vulnerabilities found: {total_vulns}")
        print(f"Total technologies detected: {total_techs}")
    
    print(f"{'='*60}\n")

def read_ips_and_domains_from_csv(csv_file):
    """Read IPv4 addresses and their corresponding domains from the CSV file."""
    ips = []
    ip_to_domain_map = {}  # Map IP addresses to their domains
    
    try:
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if 'IPv4' in row and row['IPv4'] != 'Unresolved':
                    ip = row['IPv4']
                    domain = row.get('Subdomain', '')  # Get the domain if it exists
                    
                    if ip and ip.strip():
                        ips.append(ip.strip())
                        
                        # Map this IP to its domain
                        if domain and domain.strip():
                            if ip not in ip_to_domain_map:
                                ip_to_domain_map[ip] = []
                            ip_to_domain_map[ip].append(domain.strip())
    except FileNotFoundError:
        print(f"[!] CSV file not found: {csv_file}")
    
    return list(set(ips)), ip_to_domain_map  # Remove duplicates from IPs

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
                
                f.write("PORT      PROTOCOL  STATE   SERVICE                  VERSION         FINDINGS\n")
                f.write("-" * 95 + "\n")
                
                for port, info in result['ports'].items():
                    vuln_count = len(info['vulnerabilities'])
                    tech_count = len(info['technologies'])
                    
                    findings = []
                    if vuln_count > 0:
                        findings.append(f"{vuln_count} vulnerabilities")
                    if tech_count > 0:
                        findings.append(f"{tech_count} technologies")
                    
                    findings_text = ', '.join(findings) if findings else "None"
                    service_version = info['service_version'] if info['service_version'] != "Unknown" else "-"
                    
                    f.write(f"{port:<10}{info['protocol']:<10}{info['state']:<8}{info['service_name']:<25}{service_version:<15}{findings_text}\n")
                    
                    # List technologies if found
                    if tech_count > 0:
                        f.write("\n    TECHNOLOGIES:\n")
                        for tech in info['technologies']:
                            version = f" {tech['version']}" if tech['version'] != 'Unknown' else ""
                            categories = ', '.join(tech['categories']) if tech['categories'] else 'Unknown'
                            f.write(f"    * {tech['name']}{version}\n")
                            f.write(f"      Categories: {categories}\n")
                        f.write("\n")
                    
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
        
        f.write("PORT      PROTOCOL  STATE   SERVICE                  VERSION         FINDINGS\n")
        f.write("-" * 95 + "\n")
        
        for port, info in result['ports'].items():
            vuln_count = len(info['vulnerabilities'])
            tech_count = len(info['technologies'])
            
            findings = []
            if vuln_count > 0:
                findings.append(f"{vuln_count} vulnerabilities")
            if tech_count > 0:
                findings.append(f"{tech_count} technologies")
            
            findings_text = ', '.join(findings) if findings else "None"
            service_version = info['service_version'] if info['service_version'] != "Unknown" else "-"
            
            f.write(f"{port:<10}{info['protocol']:<10}{info['state']:<8}{info['service_name']:<25}{service_version:<15}{findings_text}\n")
            
            # List technologies if found
            if tech_count > 0:
                f.write("\n    TECHNOLOGIES:\n")
                for tech in info['technologies']:
                    version = f" {tech['version']}" if tech['version'] != 'Unknown' else ""
                    categories = ', '.join(tech['categories']) if tech['categories'] else 'Unknown'
                    f.write(f"    * {tech['name']}{version}\n")
                    f.write(f"      Categories: {categories}\n")
                f.write("\n")
            
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

    # Read IPs and their corresponding domains from CSV
    print("[*] Reading IP addresses and domains from CSV...")
    ips, ip_to_domain_map = read_ips_and_domains_from_csv(input_file)
    
    if not ips:
        print("[!] No valid IP addresses found in the CSV file.")
        return

    # Scan each IP and store results
    print(f"[*] Starting port and service scan for {len(ips)} IP addresses...")
    results_list = []
    
    for i, ip in enumerate(ips, 1):
        # Get corresponding domain(s) for this IP if available
        domains = ip_to_domain_map.get(ip, [])
        domain_str = f" ({', '.join(domains)})" if domains else ""
        
        print(f"\n[*] Scanning IP {i}/{len(ips)}: {ip}{domain_str}...")
        scan_result = scan_ports_and_services(ip, domains=domains)
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