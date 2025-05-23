import whois
import pandas as pd
import os
import json
from datetime import datetime
import argparse
import sys

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

def load_domains_from_file(file_path):
    """Load domains from a text file, one domain per line."""
    try:
        with open(file_path, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
        return list(set(domains))  # Remove duplicates
    except Exception as e:
        print(f"[!] Error loading domains from {file_path}: {e}")
        return []

def load_domains_from_json(file_path):
    """Load domains from a JSON file."""
    try:
        with open(file_path, 'r') as f:
            domains = json.load(f)
        return list(set(domains))  # Remove duplicates
    except Exception as e:
        print(f"[!] Error loading domains from {file_path}: {e}")
        return []

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Domain Lease Scanner')
    parser.add_argument('--input', help='Input file containing domains (one per line)')
    args = parser.parse_args()

    # Define paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(script_dir)
    
    # Load domains from input file
    if args.input:
        print(f"[*] Reading domains from {args.input}")
        try:
            with open(args.input, 'r') as f:
                domains = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"[!] Error reading input file: {e}")
            sys.exit(1)
    else:
        print("[!] No input file provided")
        sys.exit(1)
    
    # Remove duplicates and sort
    domains = sorted(list(set(domains)))
    print(f"[+] Found {len(domains)} unique domains\n")
    
    print("Domain Lease Information:")
    print("-" * 50)
    
    results = []
    for domain in domains:
        print(f"Domain: {domain}")
        try:
            result = check_domain_lease(domain)
            if result:
                # Print with error handling for missing keys
                print(f"Status: {result.get('status', 'unknown')}")
                if result.get('status') == 'active':
                    print(f"Registrar: {result.get('registrar', 'Unknown')}")
                    print(f"Creation Date: {result.get('creation_date', 'Unknown')}")
                    print(f"Expiration Date: {result.get('expiration_date', 'Unknown')}")
                    print(f"Last Updated: {result.get('last_updated', 'Unknown')}")
                results.append(result)
            else:
                print("Status: error")
                results.append({"domain": domain, "status": "error"})
        except Exception as e:
            print(f"Status: error ({str(e)})")
            results.append({"domain": domain, "status": "error", "error": str(e)})
        print("-" * 50)
    
    # Save results to JSON
    output_file = os.path.join(base_dir, "foundData", "domainLease.json")
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Results saved to {output_file}")
    except Exception as e:
        print(f"[!] Error saving results: {e}")

if __name__ == "__main__":
    main()