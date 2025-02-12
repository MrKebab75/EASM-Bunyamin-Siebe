import csv
import subprocess
import os
from datetime import datetime

def scan_ip_for_cves(ip):
    """Scan a single IP address for vulnerabilities using nmap."""
    try:
        # Run nmap vulnerability scan
        command = ['sudo','nmap', '--script', 'vuln', ip]
        print(f"Executing command: {' '.join(command)}")
        
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(f"Scan completed for {ip}")
        
        if not result.stdout.strip():
            print(f"No output received for {ip}")
            return f"No results found for {ip}"
            
        return result.stdout
    except subprocess.CalledProcessError as e:
        error_msg = f"Error scanning {ip}: {str(e)}\nError output: {e.stderr}"
        print(error_msg)
        return error_msg

def read_ips_from_csv(csv_file):
    """Read IPv4 addresses from the CSV file."""
    ips = []
    try:
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                if row['IPv4'] != 'Unresolved':
                    # Handle multiple IPs separated by comma
                    ip_list = row['IPv4'].split(',')
                    ips.extend([ip.strip() for ip in ip_list])
    except FileNotFoundError:
        print(f"CSV file not found: {csv_file}")
        return []
    return list(set(ips))  # Remove duplicates

def write_results_to_file(results, output_file):
    """Write scan results to output file."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    with open(output_file, 'w') as f:
        f.write(f"CVE Scan Results - {timestamp}\n")
        f.write("=" * 50 + "\n\n")
        for ip, result in results.items():
            f.write(f"Results for IP: {ip}\n")
            f.write("-" * 30 + "\n")
            f.write(result + "\n\n")

def main():
    # Define file paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(script_dir)
    input_file = os.path.join(base_dir, "foundData", "subdomains_with_ips.csv")
    output_dir = os.path.join(base_dir, "foundData")
    output_file = os.path.join(output_dir, "foundCVEs.txt")

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Read IPs from CSV
    print("Reading IP addresses from CSV...")
    ips = read_ips_from_csv(input_file)
    
    if not ips:
        print("No valid IP addresses found in the CSV file.")
        return

    # Scan each IP and store results
    print(f"Starting vulnerability scan for {len(ips)} IP addresses...")
    results = {}
    for ip in ips:
        print(f"Scanning {ip}...")
        scan_result = scan_ip_for_cves(ip)
        results[ip] = scan_result

    # Write results to file
    print("Writing results to file...")
    write_results_to_file(results, output_file)
    print(f"Scan complete. Results saved to {output_file}")

if __name__ == "__main__":
    main()