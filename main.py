import os
import csv
import click
from Scripts import subdom
from Scripts import Domeingeldigheid
from Scripts import Certificaat
from Scripts import Portscan
from Scripts import CVEScanner

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
        domains = subdom.read_domains_from_file(domains_file)
        output_file = os.path.join(output_dir, "subdomains_with_ips.csv")
        with open(output_file, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(["Subdomain", "IPv4", "IPv6"])
            for dom in domains:
                results = subdom.find_subdomains_with_ips(dom)
                for entry in results:
                    csv_writer.writerow(entry)
                    csvfile.flush()
        click.echo(f"Results saved to {output_file}")
        
    elif option == "lease":
        # Domain lease check
        d = domain or click.prompt("Voer de domeinnaam in (bijv. example.com)")
        Domeingeldigheid.check_domain_lease(d)
        
    elif option == "certificate":
        # Certificate check
        d = domain or click.prompt("Voer de domeinnaam in (bijv. example.com)")
        Certificaat.check_certificate(d)
        
    elif option == "portscan":
        # Portscan
        d = domain or click.prompt("Voer de domeinnaam in (bijv. example.com)")
        Portscan.scan_with_nmap(d)
    elif option == "cvescan":
        CVEScanner.main()

if __name__ == "__main__":
    main()
