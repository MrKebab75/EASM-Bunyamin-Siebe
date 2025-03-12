import socket
import ssl
from datetime import datetime

def check_certificate(domain):
    """Check het SSL-certificaat voor de opgegeven domeinnaam."""
    context = ssl.create_default_context()
    conn = context.wrap_socket(
        socket.socket(socket.AF_INET),
        server_hostname=domain,
    )
    conn.settimeout(3)
    conn.connect((domain, 443))
    cert = conn.getpeercert()

    # Vervaldata bepalen
    not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
    issuer = dict(x[0] for x in cert['issuer'])
    subject = dict(x[0] for x in cert['subject'])

    print(f"Domein: {domain}")
    print("Uitgegeven door:", issuer.get('organizationName', 'Onbekend'))
    print("Verleend aan:", subject.get('commonName', 'Onbekend'))
    print("Vervaldatum:", not_after.strftime("%Y-%m-%d %H:%M:%S"))
    print("Nog geldig:", (not_after - datetime.utcnow()).days, "dagen")

if __name__ == "__main__":
    domeinnaam = input("Voer een domeinnaam in (bijv. 'example.com'): ")
    check_certificate(domeinnaam)

# python3 Certificaat.py