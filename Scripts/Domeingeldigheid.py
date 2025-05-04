import whois
import pandas as pd
import os
import json
from datetime import datetime

def check_domain_lease(domain):
    """Controleert de vervaldatum van een domeinnaam en geeft de details terug als een dictionary."""
    try:
        w = whois.whois(domain)
        
        # Extract creation date
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        # Extract expiration date
        expiration_date = w.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
            
        # Extract updated date
        updated_date = w.updated_date
        if isinstance(updated_date, list):
            updated_date = updated_date[0]
        
        # Calculate days remaining if expiration date exists
        days_remaining = None
        status = "unknown"
        
        if expiration_date:
            now = datetime.now()
            days_remaining = (expiration_date - now).days
            
            if days_remaining < 0:
                status = "expired"
            else:
                status = "valid"
                
        # Create result dictionary
        result = {
            "domain": domain,
            "status": status,
            "registrar": w.registrar,
            "whois_server": w.whois_server,
            "creation_date": creation_date.strftime("%Y-%m-%d") if creation_date else None,
            "expiration_date": expiration_date.strftime("%Y-%m-%d") if expiration_date else None,
            "last_updated": updated_date.strftime("%Y-%m-%d") if updated_date else None,
            "days_remaining": days_remaining,
            "name_servers": w.name_servers if hasattr(w, 'name_servers') else None,
            "registrant": w.registrant if hasattr(w, 'registrant') else None
        }
        
        return result
        
    except Exception as e:
        return {
            "domain": domain,
            "status": "error",
            "error_message": str(e)
        }

def main():
    # Define paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(script_dir)
    excel_path = os.path.join(script_dir, "Domains.xlsx")
    output_dir = os.path.join(base_dir, "foundData")
    output_file = os.path.join(output_dir, "domainLease.json")
    
    # Ensure output directory exists
    os.makedirs(output_dir, exist_ok=True)
    
    try:
        # Read domains from Excel file
        df = pd.read_excel(excel_path)
        
        if "Domain Name" not in df.columns:
            print("Error: Column 'Domain Name' not found in Excel file")
            return
            
        domains = df["Domain Name"].dropna().unique()
        print(f"Loaded {len(domains)} unique domains from Excel")
        
        # Check each domain
        results = []
        for i, domain in enumerate(domains, 1):
            print(f"[{i}/{len(domains)}] Checking domain: {domain}")
            domain_info = check_domain_lease(domain)
            results.append(domain_info)
            
            # Add a short delay to avoid overwhelming WHOIS servers
            import time
            time.sleep(1)
        
        # Save results to JSON file
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
            
        print(f"\nDomain lease information saved to {output_file}")
        
    except FileNotFoundError:
        print(f"Error: Excel file not found at {excel_path}")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()