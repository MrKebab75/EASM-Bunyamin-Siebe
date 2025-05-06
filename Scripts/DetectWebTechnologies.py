#!/usr/bin/env python3
# filepath: Scripts/DetectWebTechnologies.py

import os
import json
import time
import re
import urllib.parse
import ast
import requests
from datetime import datetime
import argparse
import csv
from urllib3.exceptions import InsecureRequestWarning

# Suppress only the InsecureRequestWarning
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
WHATRUNS_ENABLED = True

# Try to import webtech, with fallback if not available
try:
    import webtech
    WEBTECH_AVAILABLE = True
    print("[+] webtech module found. Web technology detection is enabled.")
except ImportError:
    WEBTECH_AVAILABLE = False
    print("[!] webtech module not found. Web technology detection will be limited.")
    print("[!] Run this script in a virtual environment with webtech installed:")
    print("    python3 -m venv myvenv")
    print("    source myvenv/bin/activate")
    print("    pip install webtech requests")

def detect_technologies_with_whatruns(domain, timeout=10, verbose=True):
    """
    Detect technologies using WhatRuns API.
    """
    technologies = []
    
    if verbose:
        print(f"[*] Querying WhatRuns API for {domain}...")
    
    try:
        # Use the exact same request format as your working test.py
        url = "https://www.whatruns.com/api/v1/get_site_apps"
        data = {
            "data": {
                "hostname": domain,
                "url": domain,
                "rawhostname": domain
            }
        }
        
        # Use the exact same encoding method that works in test.py
        data = urllib.parse.urlencode({k: json.dumps(v) for k, v in data.items()})
        data = data.replace('+', '')
        
        # Use the same simpler headers that work in test.py
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        
        if verbose:
            print(f"[*] Sending request to WhatRuns API...")
            
        response = requests.post(url, data=data, headers=headers, timeout=timeout)
        
        if response.status_code != 200:
            if verbose:
                print(f"[!] WhatRuns API returned status {response.status_code}")
            return technologies
        
        if verbose:
            print(f"[*] Received response, processing data...")
            
        # Parse response following the exact steps from test.py
        loaded = json.loads(response.content)
        
        # Debug output
        if verbose:
            print(f"[*] Response keys: {list(loaded.keys())}")
        
        if 'apps' not in loaded:
            if verbose:
                print(f"[!] WhatRuns API response doesn't contain 'apps' key")
                print(f"[*] Response preview: {str(loaded)[:100]}...")
            return technologies
        
        # Use the same ast.literal_eval that works in test.py
        apps = ast.literal_eval(loaded['apps'])
        
        # Use the same list conversion that works in test.py
        nuance = list(apps.keys())[0]  # Python 3 compatible
        
        # Process technologies exactly as in test.py
        for app_type, values in apps[nuance].items():
            for item in values:
                dt = datetime.fromtimestamp(item['detectedTime'] / 1000)
                ldt = datetime.fromtimestamp(item['latestDetectedTime'] / 1000)
                
                # Enhanced version extraction
                version = 'Unknown'
                if 'version' in item and item['version']:
                    version = item['version']
                # Some technologies store version in 'info' field
                elif 'info' in item and item['info']:
                    # Try to extract version from info field
                    info_str = str(item['info'])
                    # Look for version patterns like "v1.2.3" or "1.2.3"
                    version_match = re.search(r'v?(\d+\.\d+(\.\d+)*)', info_str)
                    if version_match:
                        version = version_match.group(0)
                
                technologies.append({
                    'name': item['name'],
                    'version': version,
                    'categories': [app_type],
                    'confidence': 90,
                    'detected_time': dt.strftime('%Y-%m-%d'),
                    'latest_detected': ldt.strftime('%Y-%m-%d'),
                    'detection_source': 'WhatRuns'  # Mark the source explicitly
                })
                
                if verbose:
                    version_info = f" {version}" if version != 'Unknown' else ""
                    print(f"[+] WhatRuns detected: {item['name']}{version_info} ({app_type})")
        
        if verbose:
            versions_found = sum(1 for t in technologies if t['version'] != 'Unknown')
            print(f"[+] WhatRuns found {len(technologies)} technologies ({versions_found} with version info)")
            
    except Exception as e:
        if verbose:
            print(f"[!] Error using WhatRuns API: {str(e)}")
            
    return technologies

def extract_version_from_content(response_text, tech_name):
    """
    Attempt to extract version information for a technology from page content
    using multiple patterns and approaches.
    """
    # Common version patterns for various technologies
    version_patterns = {
        # General patterns that work for many technologies
        'general': [
            # Common version comment format
            rf'{tech_name.lower()}[ -]version[=:]\s*[\'"]?([0-9][0-9.]+[0-9])[\'"]?',
            rf'v?([0-9]+\.[0-9]+(\.[0-9]+)?)[\/\-]?{tech_name.lower()}',
            rf'{tech_name.lower()}[\/\-]?v?([0-9]+\.[0-9]+(\.[0-9]+)?)',
            # Version in asset URLs
            rf'{tech_name.lower()}[/\-._]([0-9]+\.[0-9]+\.[0-9]+)',
            rf'{tech_name.lower()}[/\-._]v?([0-9]+\.[0-9]+)',
            # Meta tags sometimes contain version info
            rf'meta[^>]*{tech_name.lower()}[^>]*?content=[\'"]?[^\'">]*?([0-9]+\.[0-9]+(\.[0-9]+)?)',
            # Script file name or path pattern
            rf'{tech_name.lower()}[\-._]?v?([0-9]+\.[0-9]+(\.[0-9]+)?)\.[a-z]+',
            # Version in inline scripts
            rf'{tech_name.lower()}[\.\s]version\s*[:=]\s*[\'"]+([0-9]+\.[0-9]+(\.[0-9]+)?)',
            # Package version
            rf'[\'"]?version[\'"]?\s*:\s*[\'"]([0-9]+\.[0-9]+(\.[0-9]+)?)[\'"]',
        ],
        
        # Technology-specific patterns
        'jquery': [
            r'jquery[/\-.]([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'jquery\s*v?([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'/jquery-([0-9]+\.[0-9]+(\.[0-9]+)?)\.',
            r'jquery.min.js\?ver=([0-9]+\.[0-9]+(\.[0-9]+)?)',
        ],
        'bootstrap': [
            r'bootstrap[/\-.]([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'bootstrap\s*v?([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'/bootstrap-([0-9]+\.[0-9]+(\.[0-9]+)?)\.',
            r'bootstrap.min.css\?ver=([0-9]+\.[0-9]+(\.[0-9]+)?)',
        ],
        'wordpress': [
            r'wp-content/themes/[^/]+/style.css\?ver=([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'wp-includes/js/wp-emoji-release.min.js\?ver=([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'wp-includes/css/dist/block-library/style.min.css\?ver=([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'<meta name="generator" content="WordPress ([0-9]+\.[0-9]+(\.[0-9]+)?)"',
        ],
        'php': [
            r'php/([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'php v?([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'php.version\s*[:=]\s*[\'"]([0-9]+\.[0-9]+(\.[0-9]+)?)[\'"]',
            r'<meta name="generator" content="PHP/([0-9]+\.[0-9]+(\.[0-9]+)?)"',
        ],
        'nginx': [
            r'nginx/([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'nginx\s+v?([0-9]+\.[0-9]+(\.[0-9]+)?)',
        ],
        'apache': [
            r'apache/([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'apache\s+v?([0-9]+\.[0-9]+(\.[0-9]+)?)',
        ],
        'cloudflare': [
            r'cloudflare-nginx/([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'cloudflare/([0-9]+\.[0-9]+(\.[0-9]+)?)',
        ],
        'drupal': [
            r'drupal ([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'"drupalSettings"',  # Drupal 8+
            r'drupal.js\?v=([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'<meta name="generator" content="Drupal ([0-9]+\.[0-9]+(\.[0-9]+)?)"',
        ],
        'joomla': [
            r'joomla!?\s*([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'/joomla/templates',  # Joomla specific path
            r'<meta name="generator" content="Joomla! ([0-9]+\.[0-9]+(\.[0-9]+)?)"',
        ],
        'react': [
            r'react@([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'react[\-\.]([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'react.production.min.js\?ver=([0-9]+\.[0-9]+(\.[0-9]+)?)',
        ],
        'angular': [
            r'angular[\-\.]([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'angular@([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'angular.js\?v=([0-9]+\.[0-9]+(\.[0-9]+)?)',
        ],
        'vue': [
            r'vue@([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'vue[\-\.]([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'vue.min.js\?ver=([0-9]+\.[0-9]+(\.[0-9]+)?)',
        ],
        'google analytics': [
            r'gtag\(\'config\',\s*[\'"]GA-',  # GA4
            r'ga\(\'create\',\s*[\'"]UA-',    # Universal Analytics
        ],
        'font awesome': [
            r'font-awesome[\-\.]([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'fontawesome[\-\.]([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'font-awesome.min.css\?ver=([0-9]+\.[0-9]+(\.[0-9]+)?)',
        ],
        'shopify': [
            r'shopify[\-\.]([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'_shopify_s=',  # Cookie pattern suggests Shopify
            r'Shopify\.theme',
        ],
        'woocommerce': [
            r'woocommerce[\-\.]([0-9]+\.[0-9]+(\.[0-9]+)?)',
            r'woocommerce.min.css\?ver=([0-9]+\.[0-9]+(\.[0-9]+)?)',
        ],
    }

    # First check tech-specific patterns if available
    if tech_name.lower() in version_patterns:
        for pattern in version_patterns[tech_name.lower()]:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                # Make sure we're getting the version number, not something else
                version = match.group(1)
                if re.match(r'^[0-9]+\.[0-9]+', version):
                    return version
    
    # Then try general patterns
    for pattern in version_patterns['general']:
        try:
            match = re.search(pattern, response_text, re.IGNORECASE)
            if match:
                version = match.group(1)
                if re.match(r'^[0-9]+\.[0-9]+', version):
                    return version
        except:
            # Some regex patterns might cause issues with certain content
            # Just skip and continue
            continue
    
    return 'Unknown'

def detect_web_technologies(domain, protocol="https", timeout=10, verbose=True):
    """
    Detect web technologies running on a web domain.
    """
    technologies = []
    url = f"{protocol}://{domain}"
    
    if verbose:
        print(f"[*] Detecting web technologies on {url}")
    
    # Try to get basic server information from headers first
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive'
        }
        response = requests.get(url, timeout=timeout, verify=False, headers=headers)
        response_text = response.text.lower()
        
        # Extract version from server header if available
        server = response.headers.get('Server', '')
        if server:
            # Try to extract version from server header
            server_parts = server.split('/')
            server_name = server_parts[0]
            server_version = server_parts[1] if len(server_parts) > 1 else 'Unknown'
            
            # If version still unknown, try deeper extraction
            if server_version == 'Unknown':
                server_version = extract_version_from_content(response_text, server_name)
            
            technologies.append({
                'name': server_name,
                'version': server_version,
                'categories': ['Web Server'],
                'confidence': 90
            })
            
            if verbose:
                print(f"[+] Detected from headers: {server_name} {server_version}")
                
        # Check for common technology indicators in headers
        for header, value in response.headers.items():
            if header.lower() == 'x-powered-by':
                # Try to extract technology and version (e.g., "PHP/7.4.3")
                parts = value.split('/')
                tech_name = parts[0]
                tech_version = parts[1] if len(parts) > 1 else 'Unknown'
                
                # If version still unknown, try deeper extraction
                if tech_version == 'Unknown':
                    tech_version = extract_version_from_content(response_text, tech_name)
                
                technologies.append({
                    'name': tech_name,
                    'version': tech_version,
                    'categories': ['Web Framework'],
                    'confidence': 90
                })
                if verbose:
                    print(f"[+] Detected technology: {tech_name} {tech_version}")

    except requests.RequestException as e:
        if verbose:
            print(f"[!] Error making request to {url}: {str(e)}")
        return technologies
        
    if WEBTECH_AVAILABLE:
        # Use webtech library if available
        try:
            wt = webtech.WebTech(options={'silent': True, 'timeout': timeout})
            
            # Wrap this part in a try-except to handle different return formats
            try:
                results = wt.start_from_url(url)
                
                # Check if we got a dictionary (as expected) or something else
                if hasattr(results, 'tech'):
                    # Object with tech attribute
                    techs = results.tech
                elif isinstance(results, dict) and 'tech' in results:
                    # Dictionary with tech key
                    techs = results.get('tech', [])
                elif isinstance(results, list):
                    # List of technologies
                    techs = results
                else:
                    # Unknown format
                    if verbose:
                        print(f"[!] Unexpected result format from webtech: {type(results)}")
                    techs = []
                    
                # Process the technologies
                for tech in techs:
                    if isinstance(tech, dict):
                        # Check if we already detected this technology from headers
                        tech_name = tech.get('name', 'Unknown')
                        tech_version = tech.get('version', 'Unknown')
                        
                        # If version still unknown, try deeper extraction
                        if tech_version == 'Unknown':
                            tech_version = extract_version_from_content(response_text, tech_name)
                            
                        if not any(t['name'].lower() == tech_name.lower() for t in technologies):
                            technologies.append({
                                'name': tech_name,
                                'version': tech_version,
                                'categories': tech.get('categories', []),
                                'confidence': tech.get('confidence', 0)
                            })
            except AttributeError:
                # Handle the case where results is a string or other non-dict type
                if verbose:
                    print(f"[!] Could not process webtech results: unexpected format")
            
            if verbose and technologies:
                print(f"[+] Found {len(technologies)} technologies on {url}:")
                for tech in technologies:
                    print(f"    - {tech['name']} {tech['version']} ({', '.join(tech['categories'])})")
            elif verbose:
                print(f"[*] No technologies detected on {url}")
                
        except Exception as e:
            if verbose:
                print(f"[!] Error detecting web technologies on {url}: {str(e)}")
    else:
        # Fallback to basic content analysis if webtech is not available
        try:
            # Simple technology fingerprints
            fingerprints = {
                'wordpress': {'pattern': 'wp-content|wp-includes', 'categories': ['CMS']},
                'jquery': {'pattern': 'jquery', 'categories': ['JavaScript Library']},
                'bootstrap': {'pattern': 'bootstrap', 'categories': ['CSS Framework']},
                'php': {'pattern': 'php', 'categories': ['Programming Language']},
                'nginx': {'pattern': 'nginx', 'categories': ['Web Server']},
                'apache': {'pattern': 'apache', 'categories': ['Web Server']},
                # Additional common technologies
                'google analytics': {'pattern': 'ga\\.js|analytics\\.js|gtag', 'categories': ['Analytics']},
                'cloudflare': {'pattern': 'cloudflare', 'categories': ['CDN']},
                'react': {'pattern': 'react\\.js|react-dom', 'categories': ['JavaScript Framework']},
                'vue': {'pattern': 'vue\\.js', 'categories': ['JavaScript Framework']},
                'angular': {'pattern': 'angular\\.js|ng-app|ng-controller', 'categories': ['JavaScript Framework']},
                'font awesome': {'pattern': 'font-awesome|fontawesome', 'categories': ['Font Script']},
                'google fonts': {'pattern': 'fonts\\.googleapis\\.com', 'categories': ['Font Script']},
                'shopify': {'pattern': 'shopify', 'categories': ['E-commerce']},
                'woocommerce': {'pattern': 'woocommerce', 'categories': ['E-commerce']},
                'magento': {'pattern': 'magento', 'categories': ['E-commerce']},
                'drupal': {'pattern': 'drupal', 'categories': ['CMS']},
                'joomla': {'pattern': 'joomla', 'categories': ['CMS']},
            }
            
            for tech_name, tech_data in fingerprints.items():
                if re.search(tech_data['pattern'], response_text):
                    # Look for version
                    version = extract_version_from_content(response_text, tech_name)
                        
                    # Check if we already detected this technology
                    if not any(t['name'].lower() == tech_name for t in technologies):
                        technologies.append({
                            'name': tech_name.capitalize(),
                            'version': version,
                            'categories': tech_data['categories'],
                            'confidence': 70
                        })
                        if verbose:
                            print(f"[+] Detected technology: {tech_name.capitalize()} {version}")
                        
        except Exception as e:
            if verbose:
                print(f"[!] Error in fallback technology detection on {url}: {str(e)}")
    
    return technologies

def extract_main_domains(all_domains):
    """
    Extract unique main domains from the 'domain' field in the JSON data.
    """
    main_domains = set()
    
    for domain_data in all_domains:
        if 'domain' in domain_data:
            main_domain = domain_data['domain']
            if main_domain and main_domain != "No names were discovered":
                main_domains.add(main_domain)
    
    return list(main_domains)

def load_domains(file_path):
    """
    Load domains from JSON file.
    """
    try:
        with open(file_path, 'r') as f:
            data = json.load(f)
        return data
    except Exception as e:
        print(f"[!] Error loading domains from {file_path}: {str(e)}")
        return []

def check_technology_vulnerabilities(tech_name, version, verbose=True, api_key=None):
    """
    Check if a detected technology with given version has known vulnerabilities
    by querying vulnerability databases.
    
    Args:
        tech_name: Name of the technology to check
        version: Version string of the technology
        verbose: Whether to print verbose output
        api_key: NVD API key for higher rate limits (optional)
    """
    vulnerabilities = []
    
    if version == 'Unknown' or not version:
        if verbose:
            print(f"[*] Skipping vulnerability check for {tech_name} (unknown version)")
        return vulnerabilities
    
    try:
        # Clean up the tech name for better search results
        search_term = tech_name.lower().strip()
        
        # Common name mappings to improve search results
        name_mappings = {
            'nginx': 'nginx http server',
            'apache': 'apache http server',
            'jquery': 'jquery javascript',
            'bootstrap': 'bootstrap framework',
            'wordpress': 'wordpress cms',
            'php': 'php',
            'drupal': 'drupal cms',
            'joomla': 'joomla cms',
            'magento': 'magento',
            'shopify': 'shopify',
            'cloudflare': 'cloudflare',
        }
        
        if search_term in name_mappings:
            search_term = name_mappings[search_term]
        
        if verbose:
            print(f"[*] Checking vulnerabilities for {tech_name} {version}...")
        
        # Format version for API query
        version_clean = version.strip('v')
        
        # Cache the results locally for faster performance
        cache_dir = os.path.join("foundData", "cve_cache")
        os.makedirs(cache_dir, exist_ok=True)
        cache_file = os.path.join(cache_dir, f"{search_term.replace(' ', '_')}_{version_clean}.json")
        
        # Check if we have cached results that aren't too old (less than 24 hours)
        use_cache = False
        if os.path.exists(cache_file):
            cache_time = os.path.getmtime(cache_file)
            if time.time() - cache_time < 86400:  # 24 hours
                use_cache = True
        
        if use_cache:
            if verbose:
                print(f"[*] Using cached vulnerability data for {tech_name} {version}")
            with open(cache_file, 'r') as f:
                response_data = json.load(f)
        else:
            # Method 1: Try NIST NVD API (preferred when API key is available)
            response_data = None
            
            # Use the NIST NVD API to search for vulnerabilities
            base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
            params = {
                "keywordSearch": search_term,
                "versionStart": version_clean,
                "versionEnd": version_clean,
                "resultsPerPage": 20  # Increased from 10
            }
            
            headers = {}
            if api_key:
                # Add API key for higher rate limits if provided
                headers["apiKey"] = api_key
            
            # Sleep to respect rate limiting
            time.sleep(1)
            
            try:
                response = requests.get(base_url, params=params, headers=headers, timeout=10)
                
                if response.status_code == 200:
                    response_data = response.json()
                    
                    # Cache the results
                    with open(cache_file, 'w') as f:
                        json.dump(response_data, f)
                else:
                    if verbose:
                        print(f"[!] NVD API error: {response.status_code} {response.text}")
                        if response.status_code == 403:
                            print("[!] You may need to provide an API key for the NVD API")
                            print("[!] Get one at: https://nvd.nist.gov/developers/request-an-api-key")
            except Exception as e:
                if verbose:
                    print(f"[!] Error querying NVD API: {str(e)}")
            
            # Method 2: Try OSV Database API (alternative)
            if not response_data or 'vulnerabilities' not in response_data or not response_data['vulnerabilities']:
                if verbose:
                    print(f"[*] Trying alternative vulnerability database (OSV) for {tech_name} {version}")
                
                try:
                    # Google's Open Source Vulnerabilities Database
                    osv_url = "https://api.osv.dev/v1/query"
                    osv_data = {
                        "package": {"name": search_term},
                        "version": version_clean
                    }
                    
                    osv_response = requests.post(osv_url, json=osv_data, timeout=10)
                    
                    if osv_response.status_code == 200:
                        osv_results = osv_response.json()
                        
                        # Convert OSV results to same format as NVD for consistent processing
                        if 'vulns' in osv_results:
                            response_data = {
                                'vulnerabilities': []
                            }
                            
                            for vuln in osv_results['vulns']:
                                cve_id = next((ref for ref in vuln.get('aliases', []) if ref.startswith('CVE-')), 
                                             vuln.get('id', 'OSV-Unknown'))
                                
                                severity = "Unknown"
                                cvss_score = None
                                
                                # Extract CVSS info if available
                                for severity_info in vuln.get('severity', []):
                                    if severity_info.get('type') == 'CVSS_V3':
                                        cvss_score = severity_info.get('score')
                                        severity = get_severity_from_cvss(cvss_score)
                                
                                # Create vulnerability entry in NVD-like format for consistent processing
                                vuln_entry = {
                                    'cve': {
                                        'id': cve_id,
                                        'descriptions': [{'value': vuln.get('summary', 'No description available')}],
                                        'metrics': {}
                                    }
                                }
                                
                                if cvss_score:
                                    vuln_entry['cve']['metrics'] = {
                                        'cvssMetricV31': [{
                                            'cvssData': {
                                                'baseScore': cvss_score,
                                                'baseSeverity': severity
                                            }
                                        }]
                                    }
                                
                                response_data['vulnerabilities'].append(vuln_entry)
                            
                            # Cache the results
                            with open(cache_file, 'w') as f:
                                json.dump(response_data, f)
                except Exception as e:
                    if verbose:
                        print(f"[!] Error querying OSV API: {str(e)}")
        
        # Process the NVD API results
        if response_data and 'vulnerabilities' in response_data and response_data['vulnerabilities']:
            for vuln in response_data['vulnerabilities']:
                cve = vuln['cve']
                cve_id = cve['id']
                description = cve['descriptions'][0]['value'] if cve['descriptions'] else "No description available"
                
                # Get severity if available
                severity = "Unknown"
                cvss_score = None
                
                if 'metrics' in cve and 'cvssMetricV31' in cve['metrics']:
                    cvss_data = cve['metrics']['cvssMetricV31'][0]['cvssData']
                    severity = cvss_data.get('baseSeverity', "Unknown")
                    cvss_score = cvss_data.get('baseScore', None)
                elif 'metrics' in cve and 'cvssMetricV30' in cve['metrics']:
                    cvss_data = cve['metrics']['cvssMetricV30'][0]['cvssData']
                    severity = cvss_data.get('baseSeverity', "Unknown")
                    cvss_score = cvss_data.get('baseScore', None)
                elif 'metrics' in cve and 'cvssMetricV2' in cve['metrics']:
                    cvss_data = cve['metrics']['cvssMetricV2'][0]['cvssData']
                    score = cvss_data.get('baseScore', 0)
                    cvss_score = score
                    
                    # Map CVSS v2 score to severity
                    severity = get_severity_from_cvss(score)
                
                # Create vulnerability entry
                vulnerability = {
                    'id': cve_id,
                    'tech_name': tech_name,
                    'tech_version': version,
                    'description': description,
                    'severity': severity,
                    'cvss_score': cvss_score,
                    'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                }
                
                vulnerabilities.append(vulnerability)
                
                if verbose:
                    cvss_info = f" (CVSS: {cvss_score})" if cvss_score else ""
                    print(f"[+] Found vulnerability: {cve_id} - {severity}{cvss_info}")
            
        # Fallback to local vulnerability database if available and no results from APIs
        if not vulnerabilities:
            fallback_db_file = os.path.join("foundData", "vulnerability_db.csv")
            if os.path.exists(fallback_db_file):
                if verbose:
                    print(f"[*] Checking local vulnerability database for {tech_name} {version}")
                with open(fallback_db_file, 'r') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if search_term.lower() in row.get('product', '').lower():
                            # Check if version is affected
                            affected_version = row.get('version', '')
                            if affected_version and version_matches(version_clean, affected_version):
                                cve_id = row.get('cve_id', 'Unknown')
                                description = row.get('description', 'No description available')
                                severity = row.get('severity', 'Unknown')
                                cvss_score = float(row.get('cvss_score', 0)) if row.get('cvss_score', '').strip() else None
                                
                                # Create vulnerability entry
                                vulnerability = {
                                    'id': cve_id,
                                    'tech_name': tech_name,
                                    'tech_version': version,
                                    'description': description,
                                    'severity': severity,
                                    'cvss_score': cvss_score,
                                    'url': f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                                }
                                
                                vulnerabilities.append(vulnerability)
                                
                                if verbose:
                                    cvss_info = f" (CVSS: {cvss_score})" if cvss_score else ""
                                    print(f"[+] Found vulnerability (local DB): {cve_id} - {severity}{cvss_info}")
        
        if verbose:
            if vulnerabilities:
                print(f"[+] Found {len(vulnerabilities)} vulnerabilities for {tech_name} {version}")
            else:
                print(f"[*] No known vulnerabilities found for {tech_name} {version}")
        
        return vulnerabilities
    
    except Exception as e:
        if verbose:
            print(f"[!] Error checking vulnerabilities for {tech_name} {version}: {str(e)}")
        return vulnerabilities

def get_severity_from_cvss(score):
    """Map CVSS score to severity rating."""
    if score is None:
        return "Unknown"
    
    score = float(score)
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    else:
        return "Low"

def version_matches(detected_version, affected_version):
    """
    Check if a detected version matches an affected version pattern.
    Handles exact match, version ranges, and wildcard patterns.
    """
    # Exact match
    if detected_version == affected_version:
        return True
    
    # Range in format "x.y.z-a.b.c"
    if '-' in affected_version:
        try:
            min_version, max_version = affected_version.split('-')
            min_parts = [int(p) for p in min_version.split('.')]
            max_parts = [int(p) for p in max_version.split('.')]
            detected_parts = [int(p) for p in detected_version.split('.')]
            
            # Compare each part of the version
            return min_parts <= detected_parts <= max_parts
        except:
            pass
    
    # Wildcard match (e.g., "2.4.*")
    if '*' in affected_version:
        try:
            pattern = affected_version.replace('*', '\\d+')
            return re.match(f"^{pattern}$", detected_version) is not None
        except:
            pass
    
    # Default: only exact match
    return False

def detect_and_save_technologies(domains, output_file, max_domains=None, verbose=True):
    """
    Detect technologies for a list of domains and save results to a JSON file.
    Run all detection methods and compare results.
    """
    results = {}
    
    # Limit the number of domains if max_domains is set
    if max_domains:
        domains = domains[:max_domains]
        
    total_domains = len(domains)
    total_techs_found = 0
    total_versions_found = 0
    total_vulns_found = 0
    domains_with_techs = 0
    
    print(f"[*] Starting technology detection for {len(domains)} domains...")
    print(f"[*] Will run all detection methods and select the best results")
    
    for i, domain in enumerate(domains, 1):
        print(f"\n{'='*80}")
        print(f"[*] Processing domain {i}/{total_domains}: {domain}")
        print(f"{'-'*80}")
        
        all_technologies = {}
        
        # 1. Try WhatRuns API
        if WHATRUNS_ENABLED:
            print(f"[*] Method 1: Querying WhatRuns API for {domain}...")
            whatruns_techs = detect_technologies_with_whatruns(domain, verbose=verbose)
            all_technologies['whatruns'] = whatruns_techs
            whatruns_with_version = sum(1 for t in whatruns_techs if t['version'] != 'Unknown')
            print(f"[*] WhatRuns found {len(whatruns_techs)} technologies ({whatruns_with_version} with version info)")
        
        # 2. Try HTTPS detection with webtech/fingerprinting
        print(f"[*] Method 2: Detecting technologies with HTTPS...")
        https_techs = detect_web_technologies(domain, protocol="https", verbose=verbose)
        all_technologies['https'] = https_techs
        https_with_version = sum(1 for t in https_techs if t['version'] != 'Unknown')
        print(f"[*] HTTPS detection found {len(https_techs)} technologies ({https_with_version} with version info)")
        
        # 3. Try HTTP detection with webtech/fingerprinting
        print(f"[*] Method 3: Detecting technologies with HTTP...")
        http_techs = detect_web_technologies(domain, protocol="http", verbose=verbose)
        all_technologies['http'] = http_techs
        http_with_version = sum(1 for t in http_techs if t['version'] != 'Unknown')
        print(f"[*] HTTP detection found {len(http_techs)} technologies ({http_with_version} with version info)")
        
        # Compare results and use the best one (most technologies found)
        best_method = max(all_technologies.keys(), key=lambda k: len(all_technologies[k]))
        best_techs = all_technologies[best_method]
        
        # Combine unique technologies from all methods to get the most complete picture
        combined_techs = []
        tech_names_added = set()
        
        # Process in priority order: whatruns, https, http
        priority_order = ['whatruns', 'https', 'http']
        for method in priority_order:
            if method not in all_technologies:
                continue
                
            for tech in all_technologies[method]:
                tech_id = f"{tech['name'].lower()}_{tech['categories'][0] if tech['categories'] else ''}"
                if tech_id not in tech_names_added:
                    tech_names_added.add(tech_id)
                    # Add detection method to the tech info
                    tech['detection_method'] = method
                    combined_techs.append(tech)
        
        # Count versions in combined techs
        combined_with_version = sum(1 for t in combined_techs if t['version'] != 'Unknown')
        total_versions_found += combined_with_version
        
        print(f"{'-'*80}")
        print(f"[*] Results summary for {domain}:")
        print(f"    - WhatRuns API: {len(all_technologies.get('whatruns', []))} technologies ({whatruns_with_version if 'whatruns' in all_technologies else 0} with version)")
        print(f"    - HTTPS detection: {len(all_technologies.get('https', []))} technologies ({https_with_version} with version)")
        print(f"    - HTTP detection: {len(all_technologies.get('http', []))} technologies ({http_with_version} with version)")
        print(f"    - Best method: {best_method} with {len(best_techs)} technologies")
        print(f"    - Combined unique technologies: {len(combined_techs)} ({combined_with_version} with version info)")
        
        # Check for vulnerabilities in technologies with versions
        domain_vulns = []
        
        print(f"[*] Checking for vulnerabilities in detected technologies...")
        for tech in combined_techs:
            if tech['version'] != 'Unknown':
                vulnerabilities = check_technology_vulnerabilities(tech['name'], tech['version'], verbose=verbose)
                tech['vulnerabilities'] = vulnerabilities
                domain_vulns.extend(vulnerabilities)
                total_vulns_found += len(vulnerabilities)
        
        # Store results for this domain
        if combined_techs:
            results[domain] = {
                'technologies': combined_techs,
                'vulnerabilities': domain_vulns
            }
            domains_with_techs += 1
            total_techs_found += len(combined_techs)
            
            print(f"[+] Technologies found for {domain}:")
            for tech in combined_techs:
                version_info = ""
                if tech['version'] != 'Unknown':
                    version_info = f" \033[92mv{tech['version']}\033[0m"  # Green for found versions
                else:
                    version_info = " \033[90m(no version)\033[0m"  # Gray for unknown versions
                    
                vuln_info = ""
                if 'vulnerabilities' in tech and tech['vulnerabilities']:
                    vuln_count = len(tech['vulnerabilities'])
                    vuln_info = f" \033[91m[{vuln_count} vulnerabilities]\033[0m"  # Red for vulnerabilities
                    
                categories = ', '.join(tech['categories']) if tech['categories'] else 'Unknown'
                method = tech.get('detection_method', 'unknown')
                print(f"    - {tech['name']}{version_info} ({categories}) [via {method}]{vuln_info}")
        else:
            print(f"[!] No technologies detected for {domain}")
        
        # Pause between domains to be respectful to the APIs
        if i < total_domains:
            print(f"[*] Pausing before next domain...")
            time.sleep(1)
    
    version_percentage = (total_versions_found / total_techs_found * 100) if total_techs_found > 0 else 0
    vuln_percentage = (total_vulns_found / total_versions_found * 100) if total_versions_found > 0 else 0
    
    print(f"\n{'='*80}")
    print(f"[*] Technology detection completed:")
    print(f"    - Scanned {total_domains} domains")
    print(f"    - Found technologies on {domains_with_techs} domains ({domains_with_techs/total_domains*100:.1f}%)")
    print(f"    - Total of {total_techs_found} technologies detected")
    print(f"    - {total_versions_found} versions successfully identified ({version_percentage:.1f}%)")
    print(f"    - {total_vulns_found} vulnerabilities found in detected technologies ({vuln_percentage:.1f}% of versioned techs)")
    print(f"    - Average of {total_techs_found/domains_with_techs:.1f} technologies per domain (where found)")
    
    # Save results to JSON file
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Web technologies saved to: {output_file}")
    except Exception as e:
        print(f"[!] Error saving technologies to {output_file}: {str(e)}")
        
    return results

def main():
    parser = argparse.ArgumentParser(description="Detect web technologies for domains.")
    parser.add_argument("--input", default="foundData/all_subdomains.json", help="Path to input JSON file with subdomains")
    parser.add_argument("--output", default="foundData/web_technologies.json", help="Path to output JSON file")
    parser.add_argument("--max-domains", type=int, help="Maximum number of domains to scan")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--nvd-api-key", help="API key for NVD API (or set NVD_API_KEY environment variable)")
    args = parser.parse_args()
    
    # Print welcome message
    print("\n" + "="*80)
    print("Web Technology Detection Tool")
    print("="*80)
    
    # Create output directory if it doesn't exist
    output_dir = os.path.dirname(args.output)
    os.makedirs(output_dir, exist_ok=True)
    
    # Get NVD API key from argument, environment variable, or config file
    nvd_api_key = args.nvd_api_key
    if not nvd_api_key:
        # Try environment variable
        nvd_api_key = os.environ.get('NVD_API_KEY')
        
        # Try config file if env var not set
        if not nvd_api_key:
            config_file = os.path.join(os.path.expanduser("~"), ".nvd_api_key")
            if os.path.exists(config_file):
                try:
                    with open(config_file, 'r') as f:
                        nvd_api_key = f.read().strip()
                except:
                    pass
    
    if nvd_api_key:
        print("[+] NVD API key found. Will use it for vulnerability checks.")
    else:
        print("[!] No NVD API key found. Will use public endpoints with rate limiting.")
        print("[!] For better performance, get an API key at: https://nvd.nist.gov/developers/request-an-api-key")
        print("[!] Then use --nvd-api-key or set the NVD_API_KEY environment variable")
    
    # Load domains from file
    print(f"[*] Loading domains from {args.input}...")
    all_subdomains = load_domains(args.input)
    
    if not all_subdomains:
        print("[!] No domains found in input file.")
        return
        
    # Extract main domains
    print(f"[*] Extracting main domains from {len(all_subdomains)} subdomains...")
    main_domains = extract_main_domains(all_subdomains)
    
    # Sort domains alphabetically for consistent output
    main_domains.sort()
    
    print(f"[*] Found {len(main_domains)} unique main domains.")
    
    # Set a reasonable default if max_domains is not provided
    if args.max_domains is None:
        args.max_domains = len(main_domains) 
    
    print(f"[*] Will scan up to {args.max_domains} domains")
    print(f"[*] Verbose mode: {'Enabled' if args.verbose else 'Disabled'}")
    print(f"[*] Results will be saved to: {args.output}")
    print("-"*80)
    
    # Pass the API key to vulnerability check function through a closure
    def check_vulnerabilities_with_key(tech_name, version, verbose=args.verbose):
        return check_technology_vulnerabilities(tech_name, version, verbose, api_key=nvd_api_key)
    
    # Detect technologies and save results
    start_time = time.time()
    
    # Now we need to modify detect_and_save_technologies to use our API key
    # We'll do this with a modified local version of the function
    
    detect_and_save_technologies_with_api_key(
        main_domains, 
        args.output, 
        max_domains=args.max_domains,
        verbose=args.verbose,
        api_key=nvd_api_key
    )
    
    # Print final summary
    elapsed_time = time.time() - start_time
    minutes, seconds = divmod(elapsed_time, 60)
    print(f"[+] Web technology detection completed in {int(minutes)}m {int(seconds)}s")
    print(f"[+] Results saved to: {args.output}")
    print("="*80)

def detect_and_save_technologies_with_api_key(domains, output_file, max_domains=None, verbose=True, api_key=None):
    """
    Detect technologies for a list of domains and save results to a JSON file.
    Run all detection methods and compare results.
    
    This is a modified version of detect_and_save_technologies that accepts an API key.
    """
    results = {}
    
    # Limit the number of domains if max_domains is set
    if max_domains:
        domains = domains[:max_domains]
        
    total_domains = len(domains)
    total_techs_found = 0
    total_versions_found = 0
    total_vulns_found = 0
    domains_with_techs = 0
    
    print(f"[*] Starting technology detection for {len(domains)} domains...")
    print(f"[*] Will run all detection methods and select the best results")
    
    for i, domain in enumerate(domains, 1):
        print(f"\n{'='*80}")
        print(f"[*] Processing domain {i}/{total_domains}: {domain}")
        print(f"{'-'*80}")
        
        all_technologies = {}
        
        # 1. Try WhatRuns API
        if WHATRUNS_ENABLED:
            print(f"[*] Method 1: Querying WhatRuns API for {domain}...")
            whatruns_techs = detect_technologies_with_whatruns(domain, verbose=verbose)
            all_technologies['whatruns'] = whatruns_techs
            whatruns_with_version = sum(1 for t in whatruns_techs if t['version'] != 'Unknown')
            print(f"[*] WhatRuns found {len(whatruns_techs)} technologies ({whatruns_with_version} with version info)")
        
        # 2. Try HTTPS detection with webtech/fingerprinting
        print(f"[*] Method 2: Detecting technologies with HTTPS...")
        https_techs = detect_web_technologies(domain, protocol="https", verbose=verbose)
        all_technologies['https'] = https_techs
        https_with_version = sum(1 for t in https_techs if t['version'] != 'Unknown')
        print(f"[*] HTTPS detection found {len(https_techs)} technologies ({https_with_version} with version info)")
        
        # 3. Try HTTP detection with webtech/fingerprinting
        print(f"[*] Method 3: Detecting technologies with HTTP...")
        http_techs = detect_web_technologies(domain, protocol="http", verbose=verbose)
        all_technologies['http'] = http_techs
        http_with_version = sum(1 for t in http_techs if t['version'] != 'Unknown')
        print(f"[*] HTTP detection found {len(http_techs)} technologies ({http_with_version} with version info)")
        
        # Compare results and use the best one (most technologies found)
        best_method = max(all_technologies.keys(), key=lambda k: len(all_technologies[k]))
        best_techs = all_technologies[best_method]
        
        # Combine unique technologies from all methods to get the most complete picture
        combined_techs = []
        tech_names_added = set()
        
        # Process in priority order: whatruns, https, http
        priority_order = ['whatruns', 'https', 'http']
        for method in priority_order:
            if method not in all_technologies:
                continue
                
            for tech in all_technologies[method]:
                tech_id = f"{tech['name'].lower()}_{tech['categories'][0] if tech['categories'] else ''}"
                if tech_id not in tech_names_added:
                    tech_names_added.add(tech_id)
                    # Add detection method to the tech info
                    tech['detection_method'] = method
                    combined_techs.append(tech)
        
        # Count versions in combined techs
        combined_with_version = sum(1 for t in combined_techs if t['version'] != 'Unknown')
        total_versions_found += combined_with_version
        
        print(f"{'-'*80}")
        print(f"[*] Results summary for {domain}:")
        print(f"    - WhatRuns API: {len(all_technologies.get('whatruns', []))} technologies ({whatruns_with_version if 'whatruns' in all_technologies else 0} with version)")
        print(f"    - HTTPS detection: {len(all_technologies.get('https', []))} technologies ({https_with_version} with version)")
        print(f"    - HTTP detection: {len(all_technologies.get('http', []))} technologies ({http_with_version} with version)")
        print(f"    - Best method: {best_method} with {len(best_techs)} technologies")
        print(f"    - Combined unique technologies: {len(combined_techs)} ({combined_with_version} with version info)")
        
        # Check for vulnerabilities in technologies with versions
        domain_vulns = []
        
        print(f"[*] Checking for vulnerabilities in detected technologies...")
        for tech in combined_techs:
            if tech['version'] != 'Unknown':
                # Use enhanced vulnerability checking
                vulnerabilities = check_technology_vulnerabilities_enhanced(
                    tech['name'], tech['version'], verbose=verbose, api_key=api_key
                )
                tech['vulnerabilities'] = vulnerabilities
                domain_vulns.extend(vulnerabilities)
                total_vulns_found += len(vulnerabilities)
        
        # Store results for this domain
        if combined_techs:
            results[domain] = {
                'technologies': combined_techs,
                'vulnerabilities': domain_vulns
            }
            domains_with_techs += 1
            total_techs_found += len(combined_techs)
            
            print(f"[+] Technologies found for {domain}:")
            for tech in combined_techs:
                version_info = ""
                if tech['version'] != 'Unknown':
                    version_info = f" \033[92mv{tech['version']}\033[0m"  # Green for found versions
                else:
                    version_info = " \033[90m(no version)\033[0m"  # Gray for unknown versions
                    
                vuln_info = ""
                if 'vulnerabilities' in tech and tech['vulnerabilities']:
                    vuln_count = len(tech['vulnerabilities'])
                    vuln_info = f" \033[91m[{vuln_count} vulnerabilities]\033[0m"  # Red for vulnerabilities
                    
                categories = ', '.join(tech['categories']) if tech['categories'] else 'Unknown'
                method = tech.get('detection_method', 'unknown')
                print(f"    - {tech['name']}{version_info} ({categories}) [via {method}]{vuln_info}")
        else:
            print(f"[!] No technologies detected for {domain}")
        
        # Pause between domains to be respectful to the APIs
        if i < total_domains:
            print(f"[*] Pausing before next domain...")
            time.sleep(1)
    
    version_percentage = (total_versions_found / total_techs_found * 100) if total_techs_found > 0 else 0
    vuln_percentage = (total_vulns_found / total_versions_found * 100) if total_versions_found > 0 else 0
    
    print(f"\n{'='*80}")
    print(f"[*] Technology detection completed:")
    print(f"    - Scanned {total_domains} domains")
    print(f"    - Found technologies on {domains_with_techs} domains ({domains_with_techs/total_domains*100:.1f}%)")
    print(f"    - Total of {total_techs_found} technologies detected")
    print(f"    - {total_versions_found} versions successfully identified ({version_percentage:.1f}%)")
    print(f"    - {total_vulns_found} vulnerabilities found in detected technologies ({vuln_percentage:.1f}% of versioned techs)")
    print(f"    - Average of {total_techs_found/domains_with_techs:.1f} technologies per domain (where found)" if domains_with_techs > 0 else "    - No technologies found")
    
    # Save results to JSON file
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n[+] Web technologies saved to: {output_file}")
    except Exception as e:
        print(f"[!] Error saving technologies to {output_file}: {str(e)}")
        
    return results

def check_js_vulnerabilities_with_retirejs(library_name, version, verbose=True):
    """
    Check for vulnerabilities in JavaScript libraries using retire.js if available.
    Returns a list of vulnerabilities found.
    
    Args:
        library_name: Name of the JavaScript library
        version: Version of the library
        verbose: Whether to print verbose output
    """
    vulnerabilities = []
    
    if version == 'Unknown' or not version:
        if verbose:
            print(f"[*] Skipping retire.js check for {library_name} (unknown version)")
        return vulnerabilities
    
    # Check if retire.js is installed
    try:
        # Create temporary JSON file with library info
        import tempfile
        import json
        import subprocess
        import os
        
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, "library.json")
        
        library_data = {
            "library": library_name,
            "version": version
        }
        
        with open(temp_file, 'w') as f:
            json.dump(library_data, f)
        
        # Run retire.js on the temporary file
        if verbose:
            print(f"[*] Checking {library_name} {version} with retire.js...")
            
        retire_cmd = ["npx", "retire", "--outputformat", "json", "--outputpath", os.path.join(temp_dir, "result.json"), temp_file]
        
        try:
            result = subprocess.run(retire_cmd, capture_output=True, text=True, timeout=30)
            
            # Check if retire.js found vulnerabilities
            result_file = os.path.join(temp_dir, "result.json")
            if os.path.exists(result_file):
                with open(result_file, 'r') as f:
                    retire_results = json.load(f)
                
                # Process results
                if isinstance(retire_results, list) and retire_results:
                    for result in retire_results:
                        if 'vulnerabilities' in result:
                            for vuln in result['vulnerabilities']:
                                # Convert to our standard format
                                severity = vuln.get('severity', 'Unknown')
                                identifier = vuln.get('identifiers', {}).get('CVE', ['Unknown-CVE'])[0]
                                
                                vulnerability = {
                                    'id': identifier,
                                    'tech_name': library_name,
                                    'tech_version': version,
                                    'description': vuln.get('info', ['No description'])[0],
                                    'severity': severity,
                                    'cvss_score': None,  # Not provided by retire.js
                                    'url': vuln.get('info', [''])[1] if len(vuln.get('info', [])) > 1 else "",
                                    'source': 'retire.js'
                                }
                                
                                vulnerabilities.append(vulnerability)
                                
                                if verbose:
                                    print(f"[+] retire.js found vulnerability: {identifier} - {severity}")
        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            if verbose:
                print(f"[!] Error running retire.js: {str(e)}")
        finally:
            # Clean up temporary files
            if os.path.exists(temp_file):
                os.remove(temp_file)
            result_file = os.path.join(temp_dir, "result.json")
            if os.path.exists(result_file):
                os.remove(result_file)
            os.rmdir(temp_dir)
    
    except (ImportError, FileNotFoundError) as e:
        if verbose:
            print(f"[!] retire.js not found or could not be executed. Install with 'npm install -g retire'")
    
    return vulnerabilities

def check_python_vulnerabilities_with_safety(package_name, version, verbose=True):
    """
    Check for vulnerabilities in Python packages using 'safety' if available.
    Returns a list of vulnerabilities found.
    
    Args:
        package_name: Name of the Python package
        version: Version of the package
        verbose: Whether to print verbose output
    """
    vulnerabilities = []
    
    if version == 'Unknown' or not version:
        if verbose:
            print(f"[*] Skipping safety check for {package_name} (unknown version)")
        return vulnerabilities
    
    # Check if safety is installed
    try:
        # Create temporary requirements.txt file
        import tempfile
        import subprocess
        import os
        import json
        
        temp_dir = tempfile.mkdtemp()
        temp_file = os.path.join(temp_dir, "requirements.txt")
        
        # Create requirements.txt with the specified package and version
        with open(temp_file, 'w') as f:
            f.write(f"{package_name}=={version}\n")
        
        # Run safety check on the requirements.txt file
        if verbose:
            print(f"[*] Checking {package_name} {version} with safety...")
            
        safety_cmd = ["safety", "check", "--file", temp_file, "--output", "json", "--full-report"]
        
        try:
            result = subprocess.run(safety_cmd, capture_output=True, text=True, timeout=30)
            
            # Process the output
            if result.returncode != 0:  # safety returns non-zero when vulnerabilities are found
                try:
                    safety_results = json.loads(result.stdout)
                    
                    if 'vulnerabilities' in safety_results:
                        for vuln in safety_results['vulnerabilities']:
                            # Convert to our standard format
                            vuln_id = vuln.get('vulnerability_id', 'Unknown')
                            description = vuln.get('advisory', 'No description available')
                            
                            # Determine severity from CVSS if available
                            severity = "Unknown"
                            cvss_score = None
                            
                            if 'cvss3_score' in vuln:
                                cvss_score = vuln['cvss3_score']
                                severity = get_severity_from_cvss(cvss_score)
                            
                            # Get CVE if available
                            cve_id = next((ref for ref in vuln.get('cve', []) if ref.startswith('CVE-')), vuln_id)
                            
                            vulnerability = {
                                'id': cve_id,
                                'tech_name': package_name,
                                'tech_version': version,
                                'description': description,
                                'severity': severity,
                                'cvss_score': cvss_score,
                                'url': vuln.get('more_info_url', ''),
                                'source': 'safety'
                            }
                            
                            vulnerabilities.append(vulnerability)
                            
                            if verbose:
                                cvss_info = f" (CVSS: {cvss_score})" if cvss_score else ""
                                print(f"[+] safety found vulnerability: {cve_id} - {severity}{cvss_info}")
                except json.JSONDecodeError:
                    if verbose:
                        print(f"[!] Could not parse safety output: {result.stdout}")
        except (subprocess.TimeoutExpired, subprocess.SubprocessError) as e:
            if verbose:
                print(f"[!] Error running safety: {str(e)}")
        finally:
            # Clean up temporary files
            if os.path.exists(temp_file):
                os.remove(temp_file)
            os.rmdir(temp_dir)
    
    except (ImportError, FileNotFoundError) as e:
        if verbose:
            print(f"[!] safety not found or could not be executed. Install with 'pip install safety'")
    
    return vulnerabilities

def check_technology_vulnerabilities_enhanced(tech_name, version, verbose=True, api_key=None):
    """
    Enhanced version that checks multiple sources for vulnerabilities.
    """
    all_vulnerabilities = []
    
    # Skip if version is unknown
    if version == 'Unknown' or not version:
        if verbose:
            print(f"[*] Skipping vulnerability check for {tech_name} (unknown version)")
        return all_vulnerabilities
    
    # Determine technology type based on name or categories
    tech_type = get_technology_type(tech_name)
    
    if verbose:
        print(f"[*] Checking vulnerabilities for {tech_name} {version} (type: {tech_type})...")
    
    # 1. Try specialized tools based on technology type
    specialized_vulns = []
    
    if tech_type == 'javascript':
        # For JavaScript libraries
        specialized_vulns = check_js_vulnerabilities_with_retirejs(tech_name, version, verbose)
    elif tech_type == 'python':
        # For Python packages
        specialized_vulns = check_python_vulnerabilities_with_safety(tech_name, version, verbose)
    
    # Add specialized vulnerabilities
    if specialized_vulns:
        all_vulnerabilities.extend(specialized_vulns)
        if verbose:
            print(f"[+] Found {len(specialized_vulns)} vulnerabilities using specialized tools")
    
    # 2. Try NVD API (for all technologies)
    nvd_vulns = check_technology_vulnerabilities(tech_name, version, verbose, api_key)
    
    if nvd_vulns:
        # Filter out duplicates based on ID
        existing_ids = {v['id'] for v in all_vulnerabilities}
        unique_nvd_vulns = [v for v in nvd_vulns if v['id'] not in existing_ids]
        
        all_vulnerabilities.extend(unique_nvd_vulns)
        if verbose and unique_nvd_vulns:
            print(f"[+] Found {len(unique_nvd_vulns)} additional vulnerabilities from NVD API")
    
    # Sort vulnerabilities by severity
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
    all_vulnerabilities.sort(key=lambda v: severity_order.get(v['severity'], 5))
    
    return all_vulnerabilities

def get_technology_type(tech_name):
    """
    Determine the type of technology based on its name.
    """
    tech_name_lower = tech_name.lower()
    
    # JavaScript libraries and frameworks
    javascript_techs = [
        'jquery', 'react', 'angular', 'vue', 'backbone', 'ember', 'knockout', 
        'polymer', 'mootools', 'dojo', 'prototype', 'lodash', 'underscore',
        'moment', 'express', 'npm', 'yarn', 'bootstrap', 'foundation',
        'materialize', 'bulma', 'tailwind', 'nextjs', 'nuxt', 'gatsby'
    ]
    
    # Python packages
    python_techs = [
        'django', 'flask', 'pyramid', 'bottle', 'fastapi', 'tornado', 'twisted',
        'celery', 'sqlalchemy', 'alembic', 'pytest', 'nose', 'unittest', 
        'pandas', 'numpy', 'scipy', 'matplotlib', 'seaborn', 'plotly',
        'requests', 'urllib3', 'aiohttp', 'httpx', 'beautiful soup', 'scrapy',
        'gunicorn', 'uwsgi', 'pip', 'poetry', 'pipenv'
    ]
    
    # PHP technologies
    php_techs = [
        'php', 'laravel', 'symfony', 'codeigniter', 'yii', 'cakephp', 'zend',
        'wordpress', 'drupal', 'joomla', 'magento', 'prestashop', 'woocommerce',
        'composer', 'phpunit'
    ]
    
    # Web servers
    web_servers = [
        'nginx', 'apache', 'iis', 'tomcat', 'jetty', 'undertow', 'lighttpd',
        'caddy', 'traefik'
    ]
    
    # Databases
    databases = [
        'mysql', 'postgresql', 'mariadb', 'mongodb', 'redis', 'elasticsearch',
        'cassandra', 'neo4j', 'sqlite', 'couchdb', 'firebird', 'oracle', 'mssql',
        'db2', 'sybase'
    ]
    
    # Check type based on name
    if any(tech in tech_name_lower for tech in javascript_techs):
        return 'javascript'
    elif any(tech in tech_name_lower for tech in python_techs):
        return 'python'
    elif any(tech in tech_name_lower for tech in php_techs):
        return 'php'
    elif any(tech in tech_name_lower for tech in web_servers):
        return 'web_server'
    elif any(tech in tech_name_lower for tech in databases):
        return 'database'
    
    # Default to unknown
    return 'unknown'

if __name__ == "__main__":
    main() 