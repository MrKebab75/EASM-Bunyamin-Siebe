# import csv
# import subprocess
# import json
# from pathlib import Path
# from rich.console import Console
# from rich.table import Table


# console = Console()

# def read_domains_from_csv(file_path):
#     domains = set()
#     with open(file_path, newline='', encoding='utf-8') as csvfile:
#         reader = csv.DictReader(csvfile)
#         for row in reader:
#             subdomain = row.get("Subdomain")
#             if subdomain:
#                 domains.add("https://" + subdomain.strip())
#     return sorted(domains)

# def run_nuclei(domain):
#     output_file = f"nuclei_{domain.replace('https://', '').replace('.', '_')}.json"
#     command = [
#         "nuclei",
#         "-u", domain,
#         "-json",
#         "-o", output_file,
#         "-severity", "info,low,medium,high,critical"
#     ]
#     console.print(f"[bold yellow]Scanning:[/bold yellow] {domain}")
#     subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

#     findings = []
#     if Path(output_file).exists():
#         with open(output_file, "r") as f:
#             for line in f:
#                 try:
#                     data = json.loads(line)
#                     findings.append(data)
#                 except json.JSONDecodeError:
#                     continue
#     return findings

# def display_findings(findings, domain):
#     if not findings:
#         console.print(f"[green]No issues found for {domain}[/green]")
#         return

#     table = Table(title=f"Nuclei Findings for {domain}")
#     table.add_column("Template", style="cyan")
#     table.add_column("Severity", style="magenta")
#     table.add_column("Matched URL", style="green")

#     for finding in findings:
#         table.add_row(
#             finding.get("templateID", "N/A"),
#             finding.get("info", {}).get("severity", "unknown"),
#             finding.get("matched", "N/A")
#         )

#     console.print(table)

# if __name__ == "__main__":
#     domains = read_domains_from_csv("./foundData/subdomains_with_ips.csv")
#     for domain in domains:
#         results = run_nuclei(domain)
#         display_findings(results, domain)


import subprocess
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table

console = Console()

def run_nuclei(domain):
    output_file = f"nuclei_{domain.replace('.', '_')}.json"
    command = [
        "nuclei",
        "-u", domain,
        "-json",
        "-o", output_file,
        "-severity", "info,low,medium,high,critical"
    ]
    console.print(f"[bold yellow]Running Nuclei on:[/bold yellow] {domain}")
    subprocess.run(command, stdout=subprocess.DEVNULL)

    findings = []
    if Path(output_file).exists():
        with open(output_file, "r") as f:
            for line in f:
                try:
                    data = json.loads(line)
                    findings.append(data)
                except json.JSONDecodeError:
                    continue
    return findings

def display_findings(findings):
    if not findings:
        console.print("[green]No issues found.[/green]")
        return

    table = Table(title="Nuclei Findings")
    table.add_column("Template", style="cyan")
    table.add_column("Severity", style="magenta")
    table.add_column("Matched URL", style="green")

    for finding in findings:
        table.add_row(
            finding.get("templateID", "N/A"),
            finding.get("info", {}).get("severity", "unknown"),
            finding.get("matched", "N/A")
        )

    console.print(table)

if __name__ == "__main__":
    # Add your target domains here
    domains = [
        "https://example.com",
        "https://testphp.vulnweb.com",
        "https://demo.testfire.net"
    ]

    for domain in domains:
        results = run_nuclei(domain)
        display_findings(results)
