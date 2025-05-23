import subprocess
import socket
import json
import os
import pandas as pd
import argparse

def ping_domain(domain):
    print(f"[+] Pinging domain: {domain}")
    try:
        param = '-n' if os.name == 'nt' else '-c'
        result = subprocess.run(
            ['ping', param, '1', domain],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return result.returncode == 0
    except Exception as e:
        print(f"[!] Error pinging {domain}: {e}")
        return False

def run_amass(domain):
    print(f"[+] Running Amass for {domain}")
    try:
        result = subprocess.run(
            ['amass', 'enum', '-active', '-brute', '-d', domain],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True
        )
        return {line for line in result.stdout.strip().split('\n') if line}
    except FileNotFoundError:
        print("[!] Amass not found. Please install it and ensure it's in your PATH.")
        return set()
    except subprocess.CalledProcessError as e:
        print(f"[!] Amass failed for {domain}: {e}")
        return set()
    except Exception as e:
        print(f"[!] An unexpected error occurred running Amass for {domain}: {e}")
        return set()

def run_subfinder(domain):
    print(f"[+] Running Subfinder for {domain}")
    try:
        result = subprocess.run(
            ['subfinder', '-d', domain, '-silent'],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=True
        )
        return {line for line in result.stdout.strip().split('\n') if line}
    except FileNotFoundError:
        print("[!] Subfinder not found. Please install it and ensure it's in your PATH.")
        return set()
    except subprocess.CalledProcessError as e:
        print(f"[!] Subfinder failed for {domain}: {e}")
        return set()
    except Exception as e:
        print(f"[!] An unexpected error occurred running Subfinder for {domain}: {e}")
        return set()

def resolve_ips(subdomains):
    print(f"[+] Resolving IPs for {len(subdomains)} subdomains...")
    results = []
    count = 0
    for sub in sorted(list(subdomains)):
        count += 1
        if count % 50 == 0:
            print(f"    Resolved {count}/{len(subdomains)}...")
        try:
            ip = socket.gethostbyname(sub)
        except socket.gaierror:
            ip = None
        except Exception as e:
            print(f"[!] Error resolving {sub}: {e}")
            ip = None
        results.append({
            "subdomain": sub,
            "ip": ip
        })
    print("[+] IP resolution complete.")
    return results

def load_existing_results(output_dir="foundData", filename="all_subdomains.json", inactive_filename="inactiveDomains.json"):
    """Load existing scan results if they exist."""
    all_data_path = os.path.join(output_dir, filename)
    inactive_path = os.path.join(output_dir, filename.replace("all_subdomains.json", "inactiveDomains.json"))
    
    existing_results = []
    processed_domains = set()
    inactive_domains = []
    
    # Load main results file
    try:
        if os.path.exists(all_data_path):
            with open(all_data_path, "r") as f:
                existing_results = json.load(f)
                print(f"[+] Loaded {len(existing_results)} previously scanned domains from {all_data_path}")
                for item in existing_results:
                    processed_domains.add(item["domain"])
    except Exception as e:
        print(f"[!] Error loading existing results file: {e}")
    
    # Load inactive domains file
    try:
        if os.path.exists(inactive_path):
            with open(inactive_path, "r") as f:
                inactive_data = json.load(f)
                inactive_domains = inactive_data
                print(f"[+] Loaded {len(inactive_domains)} previously identified inactive domains")
                for domain in inactive_domains:
                    processed_domains.add(domain)
    except Exception as e:
        print(f"[!] Error loading inactive domains file: {e}")
        
    return existing_results, processed_domains, inactive_domains

def save_all_results_to_json(all_data, output_dir="foundData", filename="all_subdomains.json"):
    """Saves all domain results to JSON file."""
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    try:
        with open(path, "w") as f:
            json.dump(all_data, f, indent=2)
        print(f"\n[+] All results saved to: {path}")
    except Exception as e:
        print(f"[!] Error saving combined JSON file: {e}")

def save_inactive_domains(inactive_domains, output_dir="foundData", filename="inactiveDomains.json"):
    os.makedirs(output_dir, exist_ok=True)
    path = os.path.join(output_dir, filename)
    try:
        with open(path, "w") as f:
            json.dump(inactive_domains, f, indent=2)
        print(f"[+] Inactive domains saved to: {path}")
    except Exception as e:
        print(f"[!] Error saving inactive domains file: {e}")

def load_domains_from_file(file_path):
    """Load domains from a text file, one domain per line."""
    try:
        with open(file_path, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
        return list(set(domains))  # Remove duplicates
    except Exception as e:
        print(f"[!] Error loading domains from {file_path}: {e}")
        return []

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    excel_path = os.path.join(script_dir, "Domains.xlsx")
    base_dir = os.path.dirname(script_dir)
    output_dir = os.path.join(base_dir, "foundData")  # Default output directory
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Subdomain enumeration tool")
    parser.add_argument("--resume", action="store_true", help="Resume scanning from the last domain")
    parser.add_argument("--start-from", type=str, help="Start scanning from a specific domain")
    parser.add_argument("--input", help="Input file containing domains (one per line)")
    parser.add_argument("--output-dir", help="Directory to save output files")
    args = parser.parse_args()

    # Use provided output directory if specified
    if args.output_dir:
        output_dir = args.output_dir
        print(f"[*] Using output directory: {output_dir}")

    # Load existing results if in resume mode
    existing_results = []
    processed_domains = set()
    inactive_domains_list = []
    
    if args.resume:
        print("[*] Resume mode enabled - loading previous scan results")
        existing_results, processed_domains, inactive_domains_list = load_existing_results(output_dir)

    # Load domains from input file or Excel
    if args.input:
        print(f"[+] Loading domains from {args.input}")
        domains = load_domains_from_file(args.input)
    else:
        try:
            df = pd.read_excel(excel_path)
            if "Domain Name" not in df.columns:
                print(f"[!] Error: Column 'Domain Name' not found in {excel_path}")
                return
            domains = df["Domain Name"].dropna().unique()
        except FileNotFoundError:
            print(f"[!] Error: Excel file not found at {excel_path}")
            return
        except Exception as e:
            print(f"[!] Error reading Excel file {excel_path}: {e}")
            return
    if len(domains) == 0:
        print("[!] No domains found in the input file.")
        return
    print(f"[+] Loaded {len(domains)} unique domains from input.")

    all_domain_results = existing_results.copy()
    inactive_domains = inactive_domains_list.copy()
    domains_to_process = []

    # Filter out already processed domains
    for domain in domains:
        domain = str(domain).strip()
        if not domain:
            continue
            
        if args.start_from and domain == args.start_from:
            # If start-from is specified, begin collecting domains from here
            processed_domains.clear()
            
        if domain not in processed_domains:
            domains_to_process.append(domain)
    
    if args.resume or args.start_from:
        print(f"[*] {len(domains_to_process)} domains left to process")
    
    try:
        for i, domain in enumerate(domains_to_process, 1):
            print(f"\n=== Processing domain {i}/{len(domains_to_process)}: {domain} ===")

            if not ping_domain(domain):
                print(f"[-] Domain {domain} is unreachable. Skipping...")
                inactive_domains.append(domain)
                # Save progress after each inactive domain
                save_inactive_domains(inactive_domains, output_dir=output_dir)
                continue

            amass_results = run_amass(domain)
            subfinder_results = run_subfinder(domain)

            all_subs = (amass_results | subfinder_results) - {""}

            if not all_subs:
                print(f"[-] No subdomains found for {domain}.")
                all_domain_results.append({
                    "domain": domain,
                    "subdomains_found": 0,
                    "results": []
                })
                # Save progress after each domain
                save_all_results_to_json(all_domain_results, output_dir=output_dir)
                continue

            print(f"[+] Found {len(all_subs)} unique subdomains for {domain}.")

            enriched_results = resolve_ips(all_subs)

            all_domain_results.append({
                "domain": domain,
                "subdomains_found": len(enriched_results),
                "results": enriched_results
            })
            
            # Save progress after each domain
            save_all_results_to_json(all_domain_results, output_dir=output_dir)
            
        print("\n[+] All domains processed successfully!")
        
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Saving current progress...")
        save_all_results_to_json(all_domain_results, output_dir=output_dir)
        save_inactive_domains(inactive_domains, output_dir=output_dir)
        print("[+] Progress saved. You can resume the scan later using --resume")
    except Exception as e:
        print(f"\n[!] An error occurred: {e}")
        print("[!] Saving current progress...")
        save_all_results_to_json(all_domain_results, output_dir=output_dir)
        save_inactive_domains(inactive_domains, output_dir=output_dir)
        print("[+] Progress saved. You can resume the scan later using --resume")


if __name__ == "__main__":
    main()
