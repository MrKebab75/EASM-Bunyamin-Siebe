# import re
# import subprocess
# import json
# import os
# import pandas as pd
# from pathlib import Path
# import tldextract

# def extract_root_domain(domain):
#     """Extract the root domain (SLD.TLD) from a full domain name."""
#     # Remove wildcard prefix if present
#     if domain.startswith('*.'):
#         domain = domain[2:]
        
#     # Using tldextract which properly handles all edge cases
#     extracted = tldextract.extract(domain)
#     return f"{extracted.domain}.{extracted.suffix}"

# def run_nuclei_and_extract_domains(domain):
#     """Run nuclei scan on a domain and extract all domains from the output using regex"""
#     domains_found = set()
    
#     try:
#         print(f"Running Nuclei scan on {domain}...")
#         temp_output_file = f"nuclei_temp_output_{domain}.txt"
        
#         # Run nuclei and save output to temp file
#         result = subprocess.run(
#             ["nuclei", "-u", domain, "-j"],
#             stdout=open(temp_output_file, 'w'),
#             stderr=subprocess.PIPE,
#             text=True,
#             check=False,
#             timeout=600  # 10 minutes timeout
#         )
        
#         # Process the temp file to extract domains
#         if os.path.exists(temp_output_file):
#             with open(temp_output_file, 'r') as f:
#                 content = f.read()
            
#             # Comprehensive regex to match domain names
#             domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]'
            
#             # Find all domains in the content
#             for match in re.finditer(domain_pattern, content):
#                 domain_name = match.group(0).lower()
#                 # Skip IP addresses
#                 if not re.match(r'^[0-9\.]+$', domain_name):
#                     domains_found.add(domain_name)
            
#             # Remove the temporary file
#             os.remove(temp_output_file)
            
#             print(f"Extracted {len(domains_found)} unique domains from Nuclei scan of {domain}")
        
#     except subprocess.TimeoutExpired:
#         print(f"Nuclei timed out after 10 minutes for {domain}")
#         if os.path.exists(temp_output_file):
#             os.remove(temp_output_file)
#     except Exception as e:
#         print(f"Error running Nuclei for {domain}: {e}")
#         if os.path.exists(temp_output_file):
#             os.remove(temp_output_file)
    
#     return domains_found

# def main():
#     # Set up file paths
#     script_dir = Path(__file__).parent
#     base_dir = script_dir.parent
#     input_path = script_dir / "Domains.xlsx"
#     output_dir = base_dir / "foundData"
#     unknown_domains_path = output_dir / "unknownDomains.json"
    
#     # Create foundData directory if it doesn't exist
#     os.makedirs(output_dir, exist_ok=True)
    
#     # Load known domains from Excel
#     if not input_path.exists():
#         print(f"Excel file not found at {input_path}")
#         return

#     try:
#         df = pd.read_excel(input_path)
#         if "Domain Name" not in df.columns:
#             print("Column 'Domain Name' not found in Excel file")
#             return
            
#         # Extract root domains from the known domains
#         known_domains = set()
#         for d in df["Domain Name"].dropna().unique():
#             root_domain = extract_root_domain(d.lower())
#             known_domains.add(root_domain)
            
#         print(f"Loaded {len(known_domains)} unique root domains from Excel")
#     except Exception as e:
#         print(f"Error loading Excel file: {e}")
#         return
    
#     # Load target domain from command line or use a default
#     import sys
#     if len(sys.argv) > 1:
#         target_domain = sys.argv[1]
#     else:
#         # Use a default domain
#         target_domain = "nwg.se"
#         print(f"No domain specified, using default domain: {target_domain}")
    
#     print(f"Starting Nuclei scan on target domain: {target_domain}")
    
#     # Run Nuclei and extract domains
#     found_full_domains = run_nuclei_and_extract_domains(target_domain)
    
#     # Find unknown root domains (domains not in the known_domains list)
#     unknown_domains = []
#     for full_domain in found_full_domains:
#         root_domain = extract_root_domain(full_domain)
#         if root_domain not in known_domains:
#             unknown_domains.append(full_domain)
    
#     # Save unknown domains to JSON
#     if unknown_domains:
#         with open(unknown_domains_path, 'w') as f:
#             json.dump(unknown_domains, f, indent=2)
#         print(f"\nFound {len(unknown_domains)} unknown domains")
#         print(f"Saved to {unknown_domains_path}")
#         print("\nSample of unknown domains found:")
#         for domain in sorted(unknown_domains)[:10]:  # Show first 10 as a sample
#             print(f" - {domain}")
#         if len(unknown_domains) > 10:
#             print(f" ... and {len(unknown_domains) - 10} more")
#     else:
#         print("\nNo unknown domains found.")
    
#     print(f"\nTotal domains extracted: {len(found_full_domains)}")

# if __name__ == "__main__":
#     main()

import re
import subprocess
import json
import os
import pandas as pd
from pathlib import Path

def run_nuclei_and_extract_domains(domain):
    """Run nuclei scan on a domain and extract all domains from the output using regex"""
    domains_found = set()
    
    try:
        print(f"Running Nuclei scan on {domain}...")
        temp_output_file = f"nuclei_temp_output_{domain}.txt"
        
        # Run nuclei and save output to temp file
        result = subprocess.run(
            ["nuclei", "-u", domain, "-j"],
            stdout=open(temp_output_file, 'w'),
            stderr=subprocess.PIPE,
            text=True,
            check=False,
            timeout=600  # 10 minutes timeout
        )
        
        # Process the temp file to extract domains
        if os.path.exists(temp_output_file):
            with open(temp_output_file, 'r') as f:
                content = f.read()
            
            # Extract domains using regex patterns
            
            # Pattern for host fields in the JSON data
            host_pattern = r'"host":\s*"(?:https?://)?([^"/]+)'
            
            # Pattern for extracted results that look like domains
            extracted_pattern = r'"extracted-results":\s*\[.*?"(?!.*?@)([a-zA-Z0-9][a-zA-Z0-9\.-]+\.[a-zA-Z]{2,})"'
            
            # Pattern for DNS names in certificates
            ssl_dns_pattern = r'"ssl-dns-names".*?"extracted-results":\s*\[(.*?)\]'
            
            # Find domains in host fields
            for match in re.finditer(host_pattern, content):
                domains_found.add(match.group(1).lower())
            
            # Find domains in extracted results
            for match in re.finditer(extracted_pattern, content, re.DOTALL):
                domains_found.add(match.group(1).lower())
                
            # Find domains in SSL certificate DNS names
            for match in re.finditer(ssl_dns_pattern, content, re.DOTALL):
                dns_names = match.group(1)
                # Extract individual domain names from the DNS names list
                for domain_match in re.finditer(r'"([^"@]+\.[^"@]+)"', dns_names):
                    domain_name = domain_match.group(1).lower()
                    # Skip IP addresses
                    if not re.match(r'^[0-9\.]+$', domain_name):
                        # Remove wildcard prefix if present
                        if domain_name.startswith('*.'):
                            domain_name = domain_name[2:]
                        domains_found.add(domain_name)
            
            # Remove the temporary file
            os.remove(temp_output_file)
            
            print(f"Extracted {len(domains_found)} unique domains from Nuclei scan of {domain}")
        
    except subprocess.TimeoutExpired:
        print(f"Nuclei timed out after 10 minutes for {domain}")
        if os.path.exists(temp_output_file):
            os.remove(temp_output_file)
    except Exception as e:
        print(f"Error running Nuclei for {domain}: {e}")
        if os.path.exists(temp_output_file):
            os.remove(temp_output_file)
    
    return domains_found

def main():
    # Set up file paths
    script_dir = Path(__file__).parent
    base_dir = script_dir.parent
    input_path = script_dir / "Domains.xlsx"
    output_dir = base_dir / "foundData"
    unknown_domains_path = output_dir / "unknownDomains.json"
    
    # Create foundData directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Load known domains from Excel
    if not input_path.exists():
        print(f"Excel file not found at {input_path}")
        return

    try:
        df = pd.read_excel(input_path)
        if "Domain Name" not in df.columns:
            print("Column 'Domain Name' not found in Excel file")
            return
            
        known_domains = set(d.lower() for d in df["Domain Name"].dropna().unique())
        print(f"Loaded {len(known_domains)} known domains from Excel")
    except Exception as e:
        print(f"Error loading Excel file: {e}")
        return
    
    # Load target domain from command line or use a default
    import sys
    if len(sys.argv) > 1:
        target_domain = sys.argv[1]
    else:
        # Use first domain from Excel as default target
        target_domains = list(known_domains)
        if not target_domains:
            print("No domains found in Excel file")
            return
        target_domain = target_domains[0]
    
    print(f"Starting Nuclei scan on target domain: {target_domain}")
    
    # Run Nuclei and extract domains
    found_domains = run_nuclei_and_extract_domains(target_domain)
    
    # Find unknown domains (domains not in the known_domains list)
    unknown_domains = [d for d in found_domains if d not in known_domains]
    
    # Save unknown domains to JSON
    if unknown_domains:
        with open(unknown_domains_path, 'w') as f:
            json.dump(unknown_domains, f, indent=2)
        print(f"\nFound {len(unknown_domains)} unknown domains")
        print(f"Saved to {unknown_domains_path}")
        print("\nUnknown domains found:")
        for domain in sorted(unknown_domains):
            print(f" - {domain}")
    else:
        print("\nNo unknown domains found.")
    
    print(f"\nTotal domains extracted: {len(found_domains)}")

if __name__ == "__main__":
    main()