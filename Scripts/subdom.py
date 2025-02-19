# import subprocess
# import sys
# import csv
# import re
# import os

# # Function to clean domain (remove https://, http://, www.)
# def clean_domain(domain):
#     domain = domain.strip()
#     domain = re.sub(r'^https?://', '', domain)  # Remove http:// or https://
#     domain = re.sub(r'^www\.', '', domain)  # Remove www.
#     return domain

# # Function to classify an IP as IPv4 or IPv6
# def classify_ip(ip):
#     if ':' in ip:  # IPv6 contains colons
#         return "IPv6"
#     elif '.' in ip:  # IPv4 contains dots
#         return "IPv4"
#     return "Unknown"

# # Function to run Amass and get subdomains with IPs
# def find_subdomains_with_ips(domain):
#     print(f"Finding subdomains for {domain} using Amass...")
#     results = []
#     try:
#         # Run Amass with the -ip flag to get subdomains and their IPs
#         command = ['amass', 'enum', '-v', '-d', domain, '-ip']
#         result = subprocess.run(command, capture_output=True, text=True, check=True)

#         # Process the output
#         for line in result.stdout.splitlines():
#             parts = line.split()  # Amass outputs "subdomain IP"
#             subdomain = parts[0]  # First part is the subdomain
#             ip_addresses = parts[1:] if len(parts) > 1 else []  # Remaining parts are IPs

#             # Separate IPv4 and IPv6
#             ipv4_list = [ip for ip in ip_addresses if classify_ip(ip) == "IPv4"]
#             ipv4 = ipv4_list[0] if ipv4_list else "Unresolved"

#             ipv6 = next((ip for ip in ip_addresses if classify_ip(ip) == "IPv6"), "Unresolved")

#             results.append((subdomain, ipv4, ipv6))
#             print(f"  [+] {subdomain} -> IPv4: {ipv4}, IPv6: {ipv6}")  # Show progress
    
#     except subprocess.CalledProcessError as e:
#         print(f"Error running Amass for {domain}: {e}")

#     return results

# # Function to read and clean domains from a file
# def read_domains_from_file(file_path):
#     try:
#         with open(file_path, 'r') as f:
#             return [clean_domain(line) for line in f.readlines() if line.strip()]
#     except FileNotFoundError:
#         print(f"File {file_path} not found.")
#         sys.exit(1)

# def main():
#     # Define the output directory
#     output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "foundData")
#     domains_file = "domains.txt"
#     output_file = os.path.join(output_dir, "subdomains_with_ips.csv")

#     # Create output directory if it doesn't exist
#     os.makedirs(output_dir, exist_ok=True)

#     # Read and clean domains from the file
#     domains = read_domains_from_file(domains_file)

#     # Open CSV file for writing
#     with open(output_file, 'w', newline='') as csvfile:
#         csv_writer = csv.writer(csvfile)
#         csv_writer.writerow(["Subdomain", "IPv4", "IPv6"])  # Header row

#         # For each domain, find subdomains and resolve IPs
#         for domain in domains:
#             subdomains_with_ips = find_subdomains_with_ips(domain)
#             for subdomain, ipv4, ipv6 in subdomains_with_ips:
#                 csv_writer.writerow([subdomain, ipv4, ipv6])  # Save to CSV
#                 csvfile.flush()  # Ensure real-time writing

#     print(f"Results saved to {output_file}")

# if __name__ == "__main__":
#     main()
import asyncio
import aiofiles
import csv
import re
import os

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

# Async function to run Amass and get subdomains with IPs
async def find_subdomains_with_ips(domain):
    print(f"Finding subdomains for {domain} using Amass...")
    results = []
    try:
        # Run Amass asynchronously
        process = await asyncio.create_subprocess_exec(
            'amass', 'enum', '-v', '-d', domain, '-ip',
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, stderr = await process.communicate()

        if stderr:
            print(f"Error for {domain}: {stderr.decode()}")

        # Process the output
        for line in stdout.decode().splitlines():
            parts = line.split()  # Amass outputs "subdomain IP"
            subdomain = parts[0]  # First part is the subdomain
            ip_addresses = parts[1:] if len(parts) > 1 else []  # Remaining parts are IPs

            # Separate IPv4 and IPv6
            ipv4_list = [ip for ip in ip_addresses if classify_ip(ip) == "IPv4"]
            ipv4 = ipv4_list[0] if ipv4_list else "Unresolved"

            ipv6 = next((ip for ip in ip_addresses if classify_ip(ip) == "IPv6"), "Unresolved")

            results.append((subdomain, ipv4, ipv6))
            print(f"  [+] {subdomain} -> IPv4: {ipv4}, IPv6: {ipv6}")  # Show progress

    except Exception as e:
        print(f"Error running Amass for {domain}: {e}")

    return results

# Async function to read and clean domains from a file
async def read_domains_from_file(file_path):
    try:
        async with aiofiles.open(file_path, 'r') as f:
            lines = await f.readlines()
            return [clean_domain(line) for line in lines if line.strip()]
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        exit(1)

async def main():
    # Define the output directory
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "foundData")
    domains_file = "domains.txt"
    output_file = os.path.join(output_dir, "subdomains_with_ips.csv")

    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Read and clean domains from the file
    domains = await read_domains_from_file(domains_file)

    # Run Amass concurrently for multiple domains
    tasks = [find_subdomains_with_ips(domain) for domain in domains]
    all_results = await asyncio.gather(*tasks)  # Run all tasks concurrently

    # Write results asynchronously
    async with aiofiles.open(output_file, 'w', newline='') as csvfile:
        # Create a list to store rows
        rows = [["Subdomain", "IPv4", "IPv6"]]  # Header row
        
        # Add all results to rows
        for subdomains_with_ips in all_results:
            for subdomain, ipv4, ipv6 in subdomains_with_ips:
                rows.append([subdomain, ipv4, ipv6])
        
        # Write all rows at once
        await csvfile.write('\n'.join(','.join(row) for row in rows))

    print(f"Results saved to {output_file}")

# Run the async main function
if __name__ == "__main__":
    asyncio.run(main())
