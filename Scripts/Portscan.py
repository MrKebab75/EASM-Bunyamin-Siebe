import subprocess
import sys

def scan_with_nmap(domain):
    """Voer een portscan uit met nmap (enkel als nmap geïnstalleerd is)."""
    try:
        print("Uitvoeren van nmap scan...")
        # Bijvoorbeeld: -sV voor service-detectie; -p- om alle poorten te scannen.
        result = subprocess.run(["nmap", "-sV", "-p-", domain],
                                capture_output=True, text=True, check=True)
        print("Nmap output:\n", result.stdout)
    except subprocess.CalledProcessError as e:
        print("Er is een fout opgetreden bij het uitvoeren van nmap:", e)
    except FileNotFoundError:
        print("nmap is niet geïnstalleerd of niet gevonden in het pad.")

def main():
    if len(sys.argv) < 2:
        print("Gebruik: {} <domein>".format(sys.argv[0]))
        sys.exit(1)
    domain = sys.argv[1]
    scan_with_nmap(domain)

if __name__ == "__main__":
    main()