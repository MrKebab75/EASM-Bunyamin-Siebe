import socket
import ssl
import json
import os
from datetime import datetime
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
        not_before = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y %Z")
        not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
        issuer = dict(x[0] for x in cert['issuer'])
        subject = dict(x[0] for x in cert['subject'])
        
        # Calculate days remaining
        days_remaining = (not_after - datetime.utcnow()).days
        
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

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(script_dir)
    
    # Input and output file paths
    input_file = os.path.join(base_dir, "foundData", "all_subdomains.json")
    output_file = os.path.join(base_dir, "foundData", "certificates.json")
    
    # Create foundData directory if it doesn't exist
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    
    # Load domain data
    try:
        with open(input_file, 'r') as f:
            domains_data = json.load(f)
        print(f"Loaded {len(domains_data)} domain entries from {input_file}")
    except FileNotFoundError:
        print(f"Error: Input file {input_file} not found")
        return
    except json.JSONDecodeError:
        print(f"Error: Could not parse JSON in {input_file}")
        return
    
    # Process certificates for main domains only
    all_certificates = []
    total_domains = len(domains_data)
    
    print(f"Found {total_domains} main domains to check")
    processed = 0
    
    # Process each main domain entry
    for domain_entry in domains_data:
        domain_name = domain_entry['domain']
        processed += 1
        print(f"[{processed}/{total_domains}] Checking certificate for main domain: {domain_name}...")
        
        # Check certificate for main domain
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
        
    print(f"\nCertificate information for {processed} main domains saved to {output_file}")

if __name__ == "__main__":
    main()