import subprocess
import sys
import json
import re
import os
import time
import argparse
from datetime import datetime
import socket

def scan_with_nmap(domain):
    """Perform a port scan with nmap and return structured results."""
    try:
        print(f"[+] Performing nmap scan on {domain}...")
        # -sV for service detection, -p- for all ports
        result = subprocess.run(
            ["nmap", "-sV", "--open", domain],
            capture_output=True, text=True, timeout=1800  # 30 minute timeout
        )
        
        if result.returncode != 0:
            print(f"[!] Error executing nmap: {result.stderr}")
            return {"status": "error", "message": result.stderr}
            
        return parse_nmap_output(result.stdout, domain)
    except subprocess.TimeoutExpired:
        print(f"[!] Nmap scan timed out for {domain}")
        return {"status": "timeout", "message": "Scan timed out after 30 minutes"}
    except FileNotFoundError:
        print("[!] nmap is not installed or not found in PATH")
        return {"status": "error", "message": "nmap not found"}
    except Exception as e:
        print(f"[!] An error occurred: {e}")
        return {"status": "error", "message": str(e)}

def parse_nmap_output(output, domain):
    """Parse nmap output to extract port and service information."""
    # Initialize the structure for our scan results
    scan_result = {
        "domain": domain,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "completed",
        "ports": []
    }
    
    # Pattern to match port lines
    port_pattern = re.compile(r"^(\d+)\/(\w+)\s+(\w+)\s+(.*)$", re.MULTILINE)
    
    # Extract scan time if available
    scan_time_match = re.search(r"Nmap done.*?(\d+\.\d+) seconds", output)
    if scan_time_match:
        scan_result["scan_time"] = float(scan_time_match.group(1))
    
    # Extract host status
    if "Host is up" in output:
        scan_result["host_status"] = "up"
    elif "Host seems down" in output:
        scan_result["host_status"] = "down"
        return scan_result  # Return early if host is down
    
    # Find all port entries
    for line in output.split('\n'):
        line = line.strip()
        
        # Skip empty lines
        if not line:
            continue
        
        # Match port lines
        port_match = port_pattern.search(line)
        if port_match:
            port_num = port_match.group(1)
            protocol = port_match.group(2)
            state = port_match.group(3)
            service_info = port_match.group(4)
            
            # Extract service name and version if available
            service_name = service_info.split()[0] if service_info else "unknown"
            service_version = ' '.join(service_info.split()[1:]) if len(service_info.split()) > 1 else ""
            
            port_entry = {
                "port": int(port_num),
                "protocol": protocol,
                "state": state,
                "service": service_name,
                "version": service_version
            }
            
            scan_result["ports"].append(port_entry)
    
    # Add common port descriptions
    for port_entry in scan_result["ports"]:
        port_num = port_entry["port"]
        port_entry["description"] = get_port_description(port_num)
    
    return scan_result

def get_port_description(port):
    """Return a description of common ports."""
    port_descriptions = {
        21: "FTP - File Transfer Protocol",
        22: "SSH - Secure Shell",
        23: "Telnet - Unencrypted text communications",
        25: "SMTP - Simple Mail Transfer Protocol",
        53: "DNS - Domain Name System",
        80: "HTTP - Hypertext Transfer Protocol",
        110: "POP3 - Post Office Protocol v3",
        143: "IMAP - Internet Message Access Protocol",
        443: "HTTPS - HTTP over TLS/SSL",
        465: "SMTPS - SMTP over TLS/SSL",
        587: "SMTP - Submission (Email)",
        993: "IMAPS - IMAP over TLS/SSL",
        995: "POP3S - POP3 over TLS/SSL",
        3306: "MySQL Database",
        3389: "RDP - Remote Desktop Protocol",
        5432: "PostgreSQL Database",
        8080: "HTTP Alternate (often used for web proxies)",
        8443: "HTTPS Alternate"
    }
    
    return port_descriptions.get(port, "Unknown service")

def save_results_to_json(results, output_file):
    """Save scan results to a JSON file."""
    # Ensure the output directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    try:
        # Check if file exists and has content
        existing_data = []
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            with open(output_file, 'r') as f:
                existing_data = json.load(f)
                if not isinstance(existing_data, list):
                    existing_data = [existing_data]
        
        # Append new results (or use as initial data)
        if isinstance(results, list):
            combined_data = existing_data + results
        else:
            combined_data = existing_data + [results]
        
        # Write the combined data to the file
        with open(output_file, 'w') as f:
            json.dump(combined_data, f, indent=2)
        
        print(f"[+] Results saved to {output_file}")
        return True
    except Exception as e:
        print(f"[!] Error saving results: {e}")
        return False

def ping_host(domain):
    """Check if a host is reachable using ping."""
    try:
        # Different ping command based on OS
        if os.name == "nt":  # Windows
            ping_cmd = ["ping", "-n", "1", "-w", "2000", domain]
        else:  # Unix/Linux
            ping_cmd = ["ping", "-c", "1", "-W", "2", domain]
            
        result = subprocess.run(
            ping_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5
        )
        
        # Consider host up if either:
        # 1. Ping was successful (return code 0)
        # 2. We got a response but with errors (like "Destination Host Unreachable")
        return result.returncode == 0 or "bytes from" in result.stdout
    except Exception:
        # If ping fails, try a quick TCP connection to common ports
        try:
            for port in [80, 443]:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((domain, port))
                    sock.close()
                    if result == 0:
                        return True
                except:
                    continue
        except:
            pass
        return False

def load_domains_from_json(json_file):
    """Load domains and subdomains from the all_subdomains.json file."""
    try:
        with open(json_file, 'r') as f:
            data = json.load(f)
            
        # Extract domains and subdomains
        domains = []
        for entry in data:
            # Add main domain if present
            if "domain" in entry and entry["domain"]:
                domains.append(entry["domain"])
            
            # Add subdomains if present
            if "results" in entry:
                for subdomain_info in entry["results"]:
                    if "subdomain" in subdomain_info and subdomain_info["subdomain"]:
                        # Skip if subdomain is "No names were discovered"
                        if subdomain_info["subdomain"] != "No names were discovered":
                            domains.append(subdomain_info["subdomain"])
                
        return list(set(domains))  # Remove duplicates
    except Exception as e:
        print(f"[!] Error loading domains from {json_file}: {e}")
        return []

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
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Port Scanner for Domains')
    parser.add_argument('--input', help='Input file containing domains (one per line)')
    parser.add_argument('--output-dir', help='Directory to save output files')
    args = parser.parse_args()

    # Define paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(script_dir)
    
    # Determine output file location
    if args.output_dir:
        output_file = os.path.join(args.output_dir, "ports.json")
    else:
        output_file = os.path.join(base_dir, "foundData", "ports.json")
    
    # Load domains from input file if provided, otherwise use default JSON file
    if args.input:
        print(f"[*] Reading domains from {args.input}")
        domains = load_domains_from_file(args.input)
    else:
        input_file = os.path.join(base_dir, "foundData", "all_subdomains.json")
        print(f"[*] Reading domains from {input_file}")
        domains = load_domains_from_json(input_file)
    
    if not domains:
        print("[!] No domains found in the input file")
        sys.exit(1)
    
    print(f"[+] Found {len(domains)} unique domains")
    
    # Filter for reachable domains
    reachable_domains = []
    unreachable_domains = []
    
    print(f"[*] Checking which domains are reachable...")
    for i, domain in enumerate(domains, 1):
        print(f"[*] Testing domain {i}/{len(domains)}: {domain}", end="", flush=True)
        if ping_host(domain):
            print(" - Reachable ✓")
            reachable_domains.append(domain)
        else:
            print(" - Unreachable ✗")
            unreachable_domains.append(domain)
    
    print(f"[+] {len(reachable_domains)} domains are reachable")
    print(f"[+] {len(unreachable_domains)} domains are unreachable")
    
    if not reachable_domains:
        print("[!] No reachable domains found")
        sys.exit(1)
    
    # Remove the consent prompt since this will be run from the web interface
    print(f"\n[!] Starting port scan for {len(reachable_domains)} reachable domains")
    
    # Scan each reachable domain
    results = []
    for i, domain in enumerate(reachable_domains, 1):
        print(f"\n[+] Scanning domain {i}/{len(reachable_domains)}: {domain}")
        scan_result = scan_with_nmap(domain)
        results.append(scan_result)
        
        # Print summary
        if scan_result["status"] == "completed" and scan_result.get("host_status") == "up":
            num_ports = len(scan_result.get("ports", []))
            print(f"[+] Found {num_ports} open ports on {domain}")
            
            # Display top 5 ports for quick reference
            for i, port_info in enumerate(scan_result.get("ports", [])[:5]):
                print(f"    {port_info['port']}/{port_info['protocol']} - {port_info['service']} - {port_info['description']}")
            
            if num_ports > 5:
                print(f"    ... and {num_ports - 5} more ports")
        else:
            print(f"[!] Scan for {domain} did not complete successfully. Status: {scan_result['status']}")
        
        # Add unreachable domains with status
        for domain in unreachable_domains:
            results.append({
                "domain": domain,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": "completed",
                "host_status": "down",
                "ports": []
            })
        
        # Save results after each scan to prevent data loss
        if i % 5 == 0 or i == len(reachable_domains):
            save_results_to_json(results, output_file)
            
        # Brief pause between scans
        if i < len(reachable_domains):
            time.sleep(1)
    
    # Final save
    save_results_to_json(results, output_file)
    
    print(f"\n[+] Completed scan of {len(reachable_domains)} domains")
    print(f"[+] All results saved to {output_file}")

if __name__ == "__main__":
    main()