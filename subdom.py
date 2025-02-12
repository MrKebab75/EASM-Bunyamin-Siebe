import subprocess
import sys
import csv
import re

# Function to clean domain (remove https://, http://, www.)
def clean_domain(domain):
    domain = domain.strip()
    domain = re.sub(r'^https?://', '', domain)  # Remove http:// or https://
    domain = re.sub(r'^www\.', '', domain)  # Remove www.
    return domain

# Function to classify an IP as IPv4 or IPv6
def classify_ip(ip):
    if ':' in ip:  # IPv6 contains colons
        return "IPv6"
    elif '.' in ip:  # IPv4 contains dots
        return "IPv4"
    return "Unknown"

# Function to run Amass and get subdomains with IPs
def find_subdomains_with_ips(domain):
    print(f"Finding subdomains for {domain} using Amass...")
    results = []
    try:
        # Run Amass with the -ip flag to get subdomains and their IPs
        command = ['amass', 'enum', '-v', '-d', domain, '-ip']
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        # Process the output
        for line in result.stdout.splitlines():
            parts = line.split()  # Amass outputs "subdomain IP"
            subdomain = parts[0]  # First part is the subdomain
            ip_addresses = parts[1:] if len(parts) > 1 else []  # Remaining parts are IPs

            # Separate IPv4 and IPv6
            ipv4 = next((ip for ip in ip_addresses if classify_ip(ip) == "IPv4"), "Unresolved")
            ipv6 = next((ip for ip in ip_addresses if classify_ip(ip) == "IPv6"), "Unresolved")

            results.append((subdomain, ipv4, ipv6))
            print(f"  [+] {subdomain} -> IPv4: {ipv4}, IPv6: {ipv6}")  # Show progress
    
    except subprocess.CalledProcessError as e:
        print(f"Error running Amass for {domain}: {e}")

    return results

# Function to read and clean domains from a file
def read_domains_from_file(file_path):
    try:
        with open(file_path, 'r') as f:
            return [clean_domain(line) for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        sys.exit(1)

def main():
    domains_file = "domains.txt"
    output_file = "subdomains_with_ips.csv"

    # Read and clean domains from the file
    domains = read_domains_from_file(domains_file)

    # Open CSV file for writing
    with open(output_file, 'w', newline='') as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(["Subdomain", "IPv4", "IPv6"])  # Header row

        # For each domain, find subdomains and resolve IPs
        for domain in domains:
            subdomains_with_ips = find_subdomains_with_ips(domain)
            for subdomain, ipv4, ipv6 in subdomains_with_ips:
                csv_writer.writerow([subdomain, ipv4, ipv6])  # Save to CSV
                csvfile.flush()  # Ensure real-time writing

    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    main()
