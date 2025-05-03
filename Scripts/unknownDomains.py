import pandas as pd
import subprocess
import re
import json
import os
import platform
from pathlib import Path

def is_domain_reachable(domain):
    """Check if a domain is reachable using ping."""
    try:
        # Determine the ping command based on the operating system
        ping_cmd = []
        if platform.system().lower() == "windows":
            ping_cmd = ["ping", "-n", "1", "-w", "1000", domain]
        else:  # Linux/Mac
            ping_cmd = ["ping", "-c", "1", "-W", "1", domain]
        
        result = subprocess.run(
            ping_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False
        )
        
        # Check if ping was successful
        return result.returncode == 0
    except Exception as e:
        print(f"Error pinging {domain}: {e}")
        return False

def save_to_json(items, file_path):
    """Save a list/set of items to a JSON file."""
    try:
        # Load existing data if file exists
        existing_data = []
        if os.path.exists(file_path):
            with open(file_path, 'r') as f:
                existing_data = json.load(f)
        
        # Combine existing and new data
        all_data = sorted(set(existing_data) | set(items))
        
        # Write combined data
        with open(file_path, 'w') as f:
            json.dump(all_data, f, indent=2)
            
        return len(all_data)
    except Exception as e:
        print(f"Error saving to {file_path}: {e}")
        return 0

def run_amass(domain):
    """Run Amass to discover subdomains."""
    subdomains = set()
    try:
        print(f"Running Amass for {domain}...")
        temp_output_file = f"amass_{domain}.txt"
        
        # Run Amass with a timeout of 5 minutes
        result = subprocess.run(
            ["amass", "enum", "-d", domain, "-o", temp_output_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=300
        )
        
        # Read the results from the output file
        if os.path.exists(temp_output_file):
            with open(temp_output_file, 'r') as f:
                for line in f:
                    subdomain = line.strip().lower()
                    if subdomain:
                        subdomains.add(subdomain)
            
            # Remove the temporary file
            os.remove(temp_output_file)
        
        print(f"Amass found {len(subdomains)} subdomains for {domain}")
    except subprocess.TimeoutExpired:
        print(f"Amass timed out after 5 minutes for {domain}")
    except Exception as e:
        print(f"Error running Amass for {domain}: {e}")
    
    return subdomains

def run_subfinder(domain):
    """Run Subfinder to discover subdomains."""
    subdomains = set()
    try:
        print(f"Running Subfinder for {domain}...")
        result = subprocess.run(
            ["subfinder", "-d", domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=300
        )
        
        # Process the output
        if result.stdout:
            for line in result.stdout.split('\n'):
                subdomain = line.strip().lower()
                if subdomain:
                    subdomains.add(subdomain)
        
        print(f"Subfinder found {len(subdomains)} subdomains for {domain}")
    except subprocess.TimeoutExpired:
        print(f"Subfinder timed out after 5 minutes for {domain}")
    except Exception as e:
        print(f"Error running Subfinder for {domain}: {e}")
    
    return subdomains

def find_subdomains(domain):
    """Find subdomains using both Amass and Subfinder."""
    all_subdomains = set()
    
    # Run Amass
    amass_results = run_amass(domain)
    all_subdomains.update(amass_results)
    
    # Run Subfinder
    subfinder_results = run_subfinder(domain)
    all_subdomains.update(subfinder_results)
    
    return all_subdomains

def main():
    # Set up file paths
    script_dir = Path(__file__).parent
    input_path = script_dir / "Domains.xlsx"
    domains_txt_path = script_dir / "domains.txt"
    unknown_domains_path = script_dir / "unknownDomains.json"
    inactive_domains_path = script_dir / "inactiveDomains.json"
    
    # Load known domains from Excel
    if not input_path.exists():
        print(f"Excel file not found at {input_path}")
        return

    df = pd.read_excel(input_path)
    known_domains = set(d.lower() for d in df.iloc[:, 0].dropna().unique())
    print(f"Loaded {len(known_domains)} known domains from Excel")
    
    # Load target domains to scan
    target_domains = []
    if domains_txt_path.exists():
        with open(domains_txt_path, 'r') as f:
            target_domains = [line.strip() for line in f if line.strip()]
        print(f"Loaded {len(target_domains)} target domains from domains.txt")
    else:
        # If domains.txt doesn't exist, use a default domain for demonstration
        target_domains = ["nwg.se"]
        print("domains.txt not found, using default domain for demonstration")
    
    # Track unknown and inactive domains
    unknown_domains = set()
    inactive_domains = set()
    
    # Process each target domain
    for domain in target_domains:
        print(f"\nProcessing domain: {domain}")
        
        # Check if domain is reachable
        print(f"Checking if {domain} is reachable...")
        if not is_domain_reachable(domain):
            print(f"❌ Domain {domain} is not reachable")
            inactive_domains.add(domain)
            continue
            
        print(f"✅ Domain {domain} is reachable")
        
        # Find subdomains using Amass and Subfinder
        found_subdomains = find_subdomains(domain)
        print(f"Found {len(found_subdomains)} subdomains in total")
        
        # Filter for unknown domains
        for subdomain in found_subdomains:
            if subdomain.lower() not in known_domains:
                unknown_domains.add(subdomain.lower())
    
    # Save results
    if inactive_domains:
        inactive_count = save_to_json(inactive_domains, inactive_domains_path)
        print(f"\n⚠️ Found {len(inactive_domains)} inactive domains")
        print(f"📄 Saved to {inactive_domains_path} (total {inactive_count})")
    
    if unknown_domains:
        unknown_count = save_to_json(unknown_domains, unknown_domains_path)
        print(f"\n🔍 Found {len(unknown_domains)} unknown subdomains")
        print(f"📄 Saved to {unknown_domains_path} (total {unknown_count})")
    
    print("\n✅ Script execution completed")

if __name__ == "__main__":
    main()
