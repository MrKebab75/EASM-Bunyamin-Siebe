import csv
import click
from Scripts import subdom
from Scripts import Domeingeldigheid
from Scripts import Certificaat
from Scripts import Portscan

@click.command()
@click.argument("option", type=click.IntRange(1,4))
@click.option("--domain", help="Domain name (if required)")
@click.option("--file", "domains_file", default="domains.txt", help="Domains file for subdomain task")
def main(option, domain, domains_file):
    if option == 1:
        # Subdomain enumeration
        domains = subdom.read_domains_from_file(domains_file)
        output_file = "subdomains_with_ips.csv"
        with open(output_file, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)
            csv_writer.writerow(["Subdomain", "IPv4", "IPv6"])
            for dom in domains:
                results = subdom.find_subdomains_with_ips(dom)
                for entry in results:
                    csv_writer.writerow(entry)
                    csvfile.flush()
        click.echo(f"Results saved to {output_file}")
        
    elif option == 2:
        # Domain lease check
        d = domain or click.prompt("Voer de domeinnaam in (bijv. example.com)")
        Domeingeldigheid.check_domain_lease(d)
        
    elif option == 3:
        # Certificate check
        d = domain or click.prompt("Voer de domeinnaam in (bijv. example.com)")
        Certificaat.check_certificate(d)
        
    elif option == 4:
        # Portscan
        d = domain or click.prompt("Voer de domeinnaam in (bijv. example.com)")
        Portscan.scan_with_nmap(d)
        
if __name__ == "__main__":
    main()
