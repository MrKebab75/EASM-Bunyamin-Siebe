import os
import re
import sys
import csv
import click
import subprocess
import socket
import ssl

# --- Functions from subdom.py ---

def clean_domain(domain):
    domain = domain.strip()
    domain = re.sub(r'^https?://', '', domain)  # Remove http:// or https://
    domain = re.sub(r'^www\.', '', domain)        # Remove www.
    return domain

def classify_ip(ip):
    if ':' in ip:  # IPv6 has colons
        return "IPv6"
    elif '.' in ip:  # IPv4 has dots
        return "IPv4"
    return "Unknown"

def find_subdomains_with_ips(domain):
    click.echo(f"Finding subdomains for {domain} using Amass ...")
    results = []
    try:
        command = ['amass', 'enum', '-v', '-d', domain, '-ip']
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        for line in result.stdout.splitlines():
            parts = line.split()
            subdomain = parts[0]
            ip_addresses = parts[1:] if len(parts) > 1 else []
            ipv4_list = [ip for ip in ip_addresses if classify_ip(ip) == "IPv4"]
            ipv4 = ipv4_list[0] if ipv4_list else "Unresolved"
            ipv6 = next((ip for ip in ip_addresses if classify_ip(ip) == "IPv6"), "Unresolved")
            results.append((subdomain, ipv4, ipv6))
            click.echo(f"  [+] {subdomain} -> IPv4: {ipv4}, IPv6: {ipv6}")
    except subprocess.CalledProcessError as e:
        click.echo(f"Error running Amass for {domain}: {e}")
    return results

def read_domains_from_file(file_path):
    try:
        with open(file_path, 'r') as f:
            return [clean_domain(line) for line in f.readlines() if line.strip()]
    except FileNotFoundError:
        click.echo(f"File {file_path} not found.")
        sys.exit(1)

# --- Function from Domeingeldigheid script ---
def check_domain_lease(domain):
    click.echo(f"Checking lease status for {domain}")
    # Replace this block with the actual domain lease checking logic.
    # For now, we assume the domain is leased.
    click.echo(f"{domain} is leased.")

# --- Function from Certificaat script ---
def check_certificate(domain):
    click.echo(f"Checking certificate for {domain}")
    try:
        hostname = domain
        port = 443
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                click.echo(f"Certificate for {domain}:\n{cert}")
    except Exception as e:
        click.echo(f"Error retrieving certificate for {domain}: {e}")

# --- Main CLI command ---
@click.command()
@click.argument("option", type=click.Choice(["subdomains", "lease", "certificate", "portscan", "cvescan"]))
@click.option("--domain", help="Domain name (if required)")
@click.option("--file", "domains_file", default="Scripts/domains.txt", help="Domains file for subdomain task")
def main(option, domain, domains_file):
    if option == "subdomains":
        # Create output directory "foundData" in the project root
        output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "foundData")
        os.makedirs(output_dir, exist_ok=True)
        
        # Subdomain enumeration
        domains = read_domains_from_file(domains_file)
        output_file = os.path.join(output_dir, "subdomains_with_ips.csv")
        with open(output_file, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(["Subdomain", "IPv4", "IPv6"])
            for dom in domains:
                results = find_subdomains_with_ips(dom)
                for entry in results:
                    csv_writer.writerow(entry)
                    csvfile.flush()
        click.echo(f"Results saved to {output_file}")
        
    elif option == "lease":
        d = domain or click.prompt("Voer de domeinnaam in (bijv. example.com)")
        check_domain_lease(d)
        
    elif option == "certificate":
        d = domain or click.prompt("Voer de domeinnaam in (bijv. example.com)")
        check_certificate(d)
        
    elif option == "portscan":
        # Portscan
        d = domain or click.prompt("Voer de domeinnaam in (bijv. example.com)")
        Portscan.scan_with_nmap(d)
    elif option == "cvescan":
        CVEScanner.main()

if __name__ == "__main__":
    main()
