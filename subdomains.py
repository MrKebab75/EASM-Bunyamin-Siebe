import subprocess
import sys

# Function to run Amass to find subdomains
def find_subdomains_amass(domain):
    print(f"Finding subdomains for {domain} using Amass...")
    try:
        # Run Amass command to find subdomains
        command = ['amass', 'enum', '-d', domain, '-o', f'/subdomains/ {domain}_subdomains.txt']
        subprocess.run(command, check=True)
        print(f"Subdomains for {domain} saved to {domain}_subdomains.txt")
    except subprocess.CalledProcessError as e:
        print(f"Error running Amass for {domain}: {e}")

# Function to read domains from a file
def read_domains_from_file(file_path):
    try:
        with open(file_path, 'r') as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        sys.exit(1)

def main():
    # Path to your domain list file
    domains_file = "domains.txt"

    # Read domains from the file
    domains = read_domains_from_file(domains_file)

    # For each domain, find its subdomains using Amass
    for domain in domains:
        find_subdomains_amass(domain)

if __name__ == "__main__":
    main()
