import json
import requests
import dns.resolver
import whois
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
import pandas as pd
from datetime import datetime

class CompanyDomainAnalyzer:
    def __init__(self, viewdns_api_key=None):
        self.resolver = dns.resolver.Resolver()
        self.viewdns_api_key = viewdns_api_key
        
    def parse_email_website(self, combined_field):
        """Parse the combined email/website field"""
        websites = []
        emails = []
        
        if pd.isna(combined_field):
            return websites, emails
            
        items = [item.strip() for item in combined_field.split(',')]
        
        for item in items:
            if '@' in item:
                emails.append(item)
            elif 'www.' in item or '.com' in item or '.co.uk' in item or '.se' in item or '.ca' in item:
                websites.append(item)
                
        return websites, emails
    
    def clean_domain(self, url):
        """Extract clean domain from URL"""
        url = url.lower().strip()
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        return urlparse(url).netloc.lower()
    
    def get_dns_records(self, domain):
        """Get various DNS records for a domain"""
        records = {
            'mx': [],
            'txt': [],
            'cname': [],
            'ns': []
        }
        
        for record_type in records.keys():
            try:
                answers = self.resolver.resolve(domain, record_type)
                records[record_type] = [str(answer) for answer in answers]
            except Exception:
                continue
                
        return records
    
    def get_ssl_domains(self, domain):
        """Get domains from SSL certificates using crt.sh"""
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                domains = set()
                for cert in data:
                    names = cert.get('name_value', '').split('\n')
                    domains.update([name.lower() for name in names if name])
                return list(domains)
        except Exception:
            pass
        return []
    
    def analyze_company(self, row):
        """Analyze a single company's domains"""
        websites, emails = self.parse_email_website(row['Email/Website'])
        
        results = {
            'company_info': {
                'name': row['Company Name'],
                'address': row['Address'],
                'phone': row['Phone'],
                'raw_email_website': row['Email/Website']
            },
            'websites': websites,
            'emails': emails,
            'domains': {
                'main_domains': [],
                'email_domains': set(),
                'related_domains': set()
            },
            'findings': {
                'dns': [],
                'ssl': []
            },
            'domain_details': {}
        }
        
        # Process websites
        for website in websites:
            try:
                domain = self.clean_domain(website)
                results['domains']['main_domains'].append(domain)
                
                # Get DNS records
                dns_records = self.get_dns_records(domain)
                results['domain_details'][domain] = {
                    'dns_records': dns_records,
                    'discovery_method': 'website',
                    'first_seen': datetime.now().isoformat()
                }
                
                for record_type, records in dns_records.items():
                    for record in records:
                        results['findings']['dns'].append({
                            'source_domain': domain,
                            'record_type': record_type,
                            'value': record
                        })
                        if record_type == 'mx':
                            mx_domain = self.clean_domain(record)
                            results['domains']['related_domains'].add(mx_domain)
                
                # Get SSL domains
                ssl_domains = self.get_ssl_domains(domain)
                for ssl_domain in ssl_domains:
                    results['findings']['ssl'].append({
                        'source_domain': domain,
                        'found_domain': ssl_domain
                    })
                    results['domains']['related_domains'].add(ssl_domain)
                    
            except Exception as e:
                continue
        
        # Process email domains
        for email in emails:
            try:
                email_domain = email.split('@')[1].lower()
                results['domains']['email_domains'].add(email_domain)
                results['domains']['related_domains'].add(email_domain)
            except Exception:
                continue
        
        # Convert sets to lists for JSON serialization
        results['domains']['email_domains'] = list(results['domains']['email_domains'])
        results['domains']['related_domains'] = list(results['domains']['related_domains'])
        
        return results

    def process_csv(self, input_file, output_file):
        """Process the CSV file with company information"""
        # Read CSV, skipping the first row (;;;;)
        df = pd.read_csv(input_file, sep=';', skiprows=1)
        
        # Process each company
        with ThreadPoolExecutor(max_workers=5) as executor:
            results = list(executor.map(self.analyze_company, df.to_dict('records')))
        
        # Prepare output data
        output_data = {
            'metadata': {
                'analysis_date': datetime.now().isoformat(),
                'total_companies': len(results),
                'input_file': input_file
            },
            'results': results
        }
        
        # Write to JSON
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False)


# Example usage
if __name__ == "__main__":
    analyzer = CompanyDomainAnalyzer()
    analyzer.process_csv('Company.csv', '../foundData/domain_analysis.json')

    # analyzer = DomainAnalyzer(viewdns_api_key='c4c91bd9cc3c2baa71ca279f965debe6e70964f5')
    # analyzer.process_company_list('Company.csv', '../foundData/reverselookup.csv')