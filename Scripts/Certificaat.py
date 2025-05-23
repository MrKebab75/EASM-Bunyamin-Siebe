# import socket
# import ssl
# import json
# import os
# import argparse
# from datetime import datetime, UTC
# import time

# def check_certificate(domain):
#     """Check SSL certificate for the specified domain name and return certificate details."""
#     try:
#         context = ssl.create_default_context()
#         conn = context.wrap_socket(
#             socket.socket(socket.AF_INET),
#             server_hostname=domain,
#         )
#         conn.settimeout(5)
#         conn.connect((domain, 443))
#         cert = conn.getpeercert()
#         conn.close()

#         # Extract certificate data
#         not_before = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
#         not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
#         issuer = dict(x[0] for x in cert['issuer'])
#         subject = dict(x[0] for x in cert['subject'])
        
#         # Calculate days remaining using timezone-aware datetime
#         days_remaining = (not_after - datetime.now(UTC)).days
        
#         # Extract Subject Alternative Names (SANs)
#         alt_names = []
#         if 'subjectAltName' in cert:
#             alt_names = [x[1] for x in cert['subjectAltName'] if x[0] == 'DNS']
        
#         return {
#             "domain": domain,
#             "status": "valid",
#             "issuer": issuer.get('organizationName', 'Unknown'),
#             "subject": subject.get('commonName', 'Unknown'),
#             "valid_from": not_before.strftime("%Y-%m-%d %H:%M:%S"),
#             "valid_until": not_after.strftime("%Y-%m-%d %H:%M:%S"),
#             "days_remaining": days_remaining,
#             "expired": days_remaining <= 0,
#             "alt_names": alt_names,
#             "version": cert.get('version', 'Unknown'),
#             "serial_number": cert.get('serialNumber', 'Unknown'),
#         }
        
#     except socket.timeout:
#         return {
#             "domain": domain,
#             "status": "error",
#             "error_type": "timeout",
#             "message": "Connection timed out"
#         }
#     except ssl.SSLError as e:
#         return {
#             "domain": domain,
#             "status": "error",
#             "error_type": "ssl_error",
#             "message": str(e)
#         }
#     except socket.gaierror:
#         return {
#             "domain": domain,
#             "status": "error",
#             "error_type": "dns_error",
#             "message": "DNS resolution failed"
#         }
#     except Exception as e:
#         return {
#             "domain": domain,
#             "status": "error",
#             "error_type": "unknown_error",
#             "message": str(e)
#         }

# def load_domains_from_file(file_path):
#     """Load domains from a text file, one domain per line."""
#     try:
#         with open(file_path, 'r') as f:
#             domains = [line.strip() for line in f if line.strip()]
#         return list(set(domains))  # Remove duplicates
#     except Exception as e:
#         print(f"[!] Error loading domains from {file_path}: {e}")
#         return []

# def main():
#     # Set up argument parser
#     parser = argparse.ArgumentParser(description='SSL Certificate Checker for Domains')
#     parser.add_argument('--input', help='Input file containing domains (one per line)')
#     parser.add_argument('--output-dir', help='Directory to save output files')
#     args = parser.parse_args()

#     script_dir = os.path.dirname(os.path.abspath(__file__))
#     base_dir = os.path.dirname(script_dir)
    
#     # Determine output directory
#     if args.output_dir:
#         output_dir = args.output_dir
#     else:
#         output_dir = os.path.join(base_dir, "foundData")
    
#     # Create output directory if it doesn't exist
#     os.makedirs(output_dir, exist_ok=True)
    
#     # Input and output file paths
#     output_file = os.path.join(output_dir, "certificates.json")
    
#     # Load domain data
#     if args.input:
#         print(f"Reading domains from {args.input}")
#         try:
#             # Check if input is a JSON file
#             if args.input.endswith('.json'):
#                 with open(args.input, 'r') as f:
#                     data = json.load(f)
#                 # Extract domains from the JSON structure
#                 domains_data = []
#                 for entry in data:
#                     if "domain" in entry:
#                         domains_data.append({"domain": entry["domain"]})
#                         # Also add subdomains if they exist
#                         if "results" in entry:
#                             for subdomain in entry["results"]:
#                                 if "subdomain" in subdomain:
#                                     domains_data.append({"domain": subdomain["subdomain"]})
#             else:
#                 # Handle regular text file
#                 domains = load_domains_from_file(args.input)
#                 domains_data = [{"domain": domain} for domain in domains]
#         except Exception as e:
#             print(f"Error reading input file: {e}")
#             return
#     else:
#         print("No input file provided")
#         return
    
#     # Process certificates for all domains
#     all_certificates = []
#     total_domains = len(domains_data)
    
#     print(f"Found {total_domains} domains to check")
#     processed = 0
    
#     # Process each domain entry
#     for domain_entry in domains_data:
#         domain_name = domain_entry['domain']
#         processed += 1
#         print(f"[{processed}/{total_domains}] Checking certificate for domain: {domain_name}...")
        
#         # Check certificate for domain
#         cert_info = check_certificate(domain_name)
        
#         if cert_info['status'] == 'valid':
#             status_info = f"valid, expires in {cert_info['days_remaining']} days"
#             if cert_info['days_remaining'] < 30:
#                 status_info += " (EXPIRING SOON)"
#             elif cert_info['expired']:
#                 status_info += " (EXPIRED)"
#         else:
#             status_info = f"error: {cert_info['error_type']}"
            
#         print(f"  - Status: {status_info}")
        
#         # Add domain certificate to the main list
#         all_certificates.append(cert_info)
        
#         # Rate limiting to avoid overwhelming servers
#         time.sleep(0.5)
    
#     # Save results
#     with open(output_file, 'w') as f:
#         json.dump(all_certificates, f, indent=2)
        
#     print(f"\nCertificate information for {processed} domains saved to {output_file}")

# if __name__ == "__main__":
#     main()

import socket
import ssl
import json
import os
import argparse
from datetime import datetime, timezone
import time

def check_certificate(domain):
    """Check SSL certificate for the specified domain name and return certificate details."""
    try:
        context = ssl.create_default_context()
        conn = context.wrap_socket(
            socket.socket(socket.AF_INET),
            server_hostname=domain,
        )
        conn.settimeout(5)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()

        # Extract certificate data
        not_before = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        issuer = dict(x[0] for x in cert['issuer'])
        subject = dict(x[0] for x in cert['subject'])
        
        # Calculate days remaining using timezone-aware datetime
        days_remaining = (not_after - datetime.now(timezone.utc)).days
        
        # Extract Subject Alternative Names (SANs)
        alt_names = []
        if 'subjectAltName' in cert:
            alt_names = [x[1] for x in cert['subjectAltName'] if x[0] == 'DNS']
        
        return {
            "domain": domain,
            "status": "valid",
            "issuer": issuer.get('organizationName', 'Unknown'),
            "subject": subject.get('commonName', 'Unknown'),
            "valid_from": not_before.strftime("%Y-%m-%d %H:%M:%S"),
            "valid_until": not_after.strftime("%Y-%m-%d %H:%M:%S"),
            "days_remaining": days_remaining,
            "expired": days_remaining <= 0,
            "alt_names": alt_names,
            "version": cert.get('version', 'Unknown'),
            "serial_number": cert.get('serialNumber', 'Unknown'),
        }
        
    except socket.timeout:
        return {
            "domain": domain,
            "status": "error",
            "error_type": "timeout",
            "message": "Connection timed out"
        }
    except ssl.SSLError as e:
        return {
            "domain": domain,
            "status": "error",
            "error_type": "ssl_error",
            "message": str(e)
        }
    except socket.gaierror:
        return {
            "domain": domain,
            "status": "error",
            "error_type": "dns_error",
            "message": "DNS resolution failed"
        }
    except Exception as e:
        return {
            "domain": domain,
            "status": "error",
            "error_type": "unknown_error",
            "message": str(e)
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

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='SSL Certificate Checker for Domains')
    parser.add_argument('--input', help='Input file containing domains (one per line)')
    parser.add_argument('--output-dir', help='Directory to save output files')
    args = parser.parse_args()

    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(script_dir)
    
    # Determine output directory
    if args.output_dir:
        output_dir = args.output_dir
    else:
        output_dir = os.path.join(base_dir, "foundData")
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Input and output file paths
    output_file = os.path.join(output_dir, "certificates.json")
    
    # Load domain data
    if args.input:
        print(f"Reading domains from {args.input}")
        try:
            # Check if input is a JSON file
            if args.input.endswith('.json'):
                with open(args.input, 'r') as f:
                    data = json.load(f)
                # Extract domains from the JSON structure
                domains_data = []
                for entry in data:
                    if "domain" in entry:
                        domains_data.append({"domain": entry["domain"]})
                        # Also add subdomains if they exist
                        if "results" in entry:
                            for subdomain in entry["results"]:
                                if "subdomain" in subdomain:
                                    domains_data.append({"domain": subdomain["subdomain"]})
            else:
                # Handle regular text file
                domains = load_domains_from_file(args.input)
                domains_data = [{"domain": domain} for domain in domains]
        except Exception as e:
            print(f"Error reading input file: {e}")
            return
    else:
        print("No input file provided")
        return
    
    # Process certificates for all domains
    all_certificates = []
    total_domains = len(domains_data)
    
    print(f"Found {total_domains} domains to check")
    processed = 0
    
    # Process each domain entry
    for domain_entry in domains_data:
        domain_name = domain_entry['domain']
        processed += 1
        print(f"[{processed}/{total_domains}] Checking certificate for domain: {domain_name}...")
        
        # Check certificate for domain
        cert_info = check_certificate(domain_name)
        
        if cert_info['status'] == 'valid':
            status_info = f"valid, expires in {cert_info['days_remaining']} days"
            if cert_info['days_remaining'] < 30:
                status_info += " (EXPIRING SOON)"
            elif cert_info['expired']:
                status_info += " (EXPIRED)"
        else:
            status_info = f"error: {cert_info['error_type']}"
            
        print(f"  - Status: {status_info}")
        
        # Add domain certificate to the main list
        all_certificates.append(cert_info)
        
        # Rate limiting to avoid overwhelming servers
        time.sleep(0.5)
    
    # Save results
    with open(output_file, 'w') as f:
        json.dump(all_certificates, f, indent=2)
        
    print(f"\nCertificate information for {processed} domains saved to {output_file}")

if __name__ == "__main__":
    main()
