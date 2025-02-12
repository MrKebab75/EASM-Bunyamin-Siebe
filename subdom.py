# import subprocess
# import sys

# # Function to run Amass to find subdomains
# def find_subdomains_amass(domain):
#     print(f"Finding subdomains for {domain} using Amass...")
#     try:
#         # Run Amass command to find subdomains
#         command = ['amass', 'enum', '-d', domain, '-o', f'{domain}_subdomains.txt']
#         subprocess.run(command, check=True)
#         print(f"Subdomains for {domain} saved to {domain}_subdomains.txt")
#     except subprocess.CalledProcessError as e:
#         print(f"Error running Amass for {domain}: {e}")

# # Function to read domains from a file
# def read_domains_from_file(file_path):
#     try:
#         with open(file_path, 'r') as f:
#             return [line.strip() for line in f.readlines() if line.strip()]
#     except FileNotFoundError:
#         print(f"File {file_path} not found.")
#         sys.exit(1)

# def main():
#     # Path to your domain list file
#     domains_file = "domains.txt"

#     # Read domains from the file
#     domains = read_domains_from_file(domains_file)

#     # For each domain, find its subdomains using Amass
#     for domain in domains:
#         find_subdomains_amass(domain)

# if __name__ == "__main__":
#     main()


import subprocess
import sys
import csv
import socket
import re

# Function to clean domain (remove https://, http://, www.)
def clean_domain(domain):
    domain = domain.strip()
    domain = re.sub(r'^https?://', '', domain)  # Remove http:// or https://
    domain = re.sub(r'^www\.', '', domain)  # Remove www.
    return domain

# Function to run Amass to find subdomains
def find_subdomains_amass(domain):
    print(f"Finding subdomains for {domain} using Amass...")
    subdomains = []
    try:
        # Run Amass and capture output
        command = ['amass', 'enum', '-d', domain]
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        # Process the output and collect subdomains
        subdomains = result.stdout.splitlines()
    except subprocess.CalledProcessError as e:
        print(f"Error running Amass for {domain}: {e}")

    return subdomains

# Function to resolve a subdomain to an IP address
def resolve_ip(subdomain):
    try:
        return socket.gethostbyname(subdomain)
    except socket.gaierror:
        return "Unresolved"

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
        csv_writer.writerow(["Subdomain", "IP Address"])  # Header row

        # For each domain, find subdomains and resolve IPs
        for domain in domains:
            subdomains = find_subdomains_amass(domain)
            for subdomain in subdomains:
                ip_address = resolve_ip(subdomain)
                csv_writer.writerow([subdomain, ip_address])  # Save to CSV

    print(f"Results saved to {output_file}")

if __name__ == "__main__":
    main()
