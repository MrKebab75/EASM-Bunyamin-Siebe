import whois
from datetime import datetime

def check_domain_lease(domain):
    try:
        w = whois.whois(domain)
        expiration_date = w.expiration_date
        # Als er meerdere datums zijn, gebruik dan de eerste instantie
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if not expiration_date:
            print("Kon de vervaldatum voor de domeinnaam niet vinden.")
            return
        now = datetime.now()
        days_remaining = (expiration_date - now).days
        if days_remaining < 0:
            print(f"Domeinnaam '{domain}' is verlopen sinds {expiration_date.date()}.")
        else:
            print(f"Domeinnaam '{domain}' verloopt over {days_remaining} dagen op {expiration_date.date()}.")
    except Exception as e:
        print(f"Er is een fout opgetreden bij het opvragen van de domeingegevens: {e}")

if __name__ == "__main__":
    domain = input("Voer de domeinnaam in (bijv. example.com): ")
    check_domain_lease(domain)

# python3 Domeingeldigheid.py
