import requests
import re
import time
import os
import argparse
import random
import json
from stem import Signal
from stem.control import Controller
from bs4 import BeautifulSoup

# Constants
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 11.5; rv:90.0) Gecko/20100101 Firefox/90.0'
]

# Dark web search engines (onion addresses)
SEARCH_ENGINES = {
    "Ahmia": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={}"
    # Commented out engines that frequently fail with connection errors
    # "Torch": "http://torchqsxkllrj2eqaitp5xvcgfeg3g5dr3bm33aoottd4rhvykr7aqid.onion/search?query={}&action=search",
    # "DarkSearch": "http://darksearch777.onion/search?query={}",
    # "NotEvil": "http://hss3uro2hsxfogfq.onion/index.php?q={}",
    # "Haystack": "http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/?q={}",
    # "Kilos": "http://mlyusr6htlxsyc7t2f4z53wdxh3win7q3qpxcrbam6jf3dmua7tnzuyd.onion/search?q={}"
}

# Specialized leak/breach focused onion sites (these are examples; add real working ones as needed)
LEAK_SITES = {
    "BreachForums": "http://breached65xqh64s7xbkvqgg7bmj4nj7656hcb7x4g42x753r7zmejqd.onion/search.php?keywords={}",
    "LeakDatabase": "http://leakdbpknwvqkxcfgn522rkyaextgf4rugm4d5jg46h7yiudhxjgyqd.onion/search?query={}"
}

# Keywords to append to search terms to find leaked data
LEAK_KEYWORDS = [
    "leak", "breach", "database", "dump", "credentials", 
    "passwords", "emails", "accounts", "hacked", "compromised"
]

# Search engine specific parsers
def parse_torch_results(soup):
    results = []
    for result in soup.select('.result'):
        link = result.select_one('a')
        if link and '.onion' in link['href']:
            results.append({
                'url': link['href'],
                'text': link.get_text().strip()
            })
    return results

def parse_ahmia_results(soup):
    results = []
    for result in soup.select('.result'):
        link = result.select_one('a')
        if link and '.onion' in link.get('href', ''):
            results.append({
                'url': link['href'],
                'text': result.get_text().strip()
            })
    return results

# Dict mapping engines to their specific parser functions
ENGINE_PARSERS = {
    "Torch": parse_torch_results,
    "Ahmia": parse_ahmia_results,
    # Default parser is used for other engines
}

def setup_tor_session():
    """
    Set up a requests session that routes through the Tor SOCKS proxy
    """
    session = requests.session()
    # Specify the proxy configuration for Tor (default Tor SOCKS port)
    session.proxies = {
        'http': 'socks5h://127.0.0.1:9050',
        'https': 'socks5h://127.0.0.1:9050'
    }
    return session

def get_new_tor_identity():
    """
    Request a new identity from the Tor network
    """
    try:
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()  # Provide password if needed
            controller.signal(Signal.NEWNYM)
            print("[*] New Tor identity requested")
            time.sleep(5)  # Wait for the new identity to be established
    except Exception as e:
        print(f"[!] Error requesting new Tor identity: {e}")

def enhance_search_term(search_term, leak_focused=False):
    """
    Enhance search term with additional keywords to target leaked data
    """
    if not leak_focused:
        return search_term
        
    # Create variations of the search with leak-related keywords
    enhanced_terms = []
    for keyword in LEAK_KEYWORDS:
        enhanced_terms.append(f"{search_term} {keyword}")
    
    # Add more targeted queries
    enhanced_terms.append(f"{search_term} database download")
    enhanced_terms.append(f"{search_term} credentials pastebin")
    enhanced_terms.append(f"{search_term} leaked accounts")
    
    return enhanced_terms

def search_onion_site(session, search_term, url_template, output_file, engine_name, results_data):
    """
    Search a specific onion search engine with improved error handling and logging
    """
    # If it's just a string (not enhanced), make it a single-item list
    if isinstance(search_term, str):
        search_terms = [search_term]
    else:
        search_terms = search_term
    
    all_results = 0
    
    for term in search_terms:
        url = url_template.format(term)
        headers = {'User-Agent': random.choice(USER_AGENTS)}
        
        try:
            print(f"[*] Attempting to connect to {engine_name} with term: {term}")
            response = session.get(url, headers=headers, timeout=45)
            
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Use engine-specific parser if available, otherwise use generic parser
                if engine_name in ENGINE_PARSERS:
                    results = ENGINE_PARSERS[engine_name](soup)
                else:
                    # Generic parser
                    results = []
                    for link in soup.find_all('a', href=True):
                        href = link['href']
                        if '.onion' in href and not href.startswith('#'):
                            result = {
                                'url': href,
                                'text': link.get_text().strip(),
                                'search_term': term
                            }
                            if result['text'] and len(result['text']) > 5:
                                results.append(result)
                
                # Filter results to prioritize those likely containing leaked data
                filtered_results = filter_leak_focused_results(results)
                
                # Store results in the data structure
                if filtered_results:
                    if engine_name not in results_data['engines']:
                        results_data['engines'][engine_name] = []
                    
                    results_data['engines'][engine_name].extend(filtered_results)
                    results_data['total_results'] += len(filtered_results)
                    all_results += len(filtered_results)
                    
                    print(f"[+] Found {len(filtered_results)} relevant results from {engine_name} for '{term}'")
            else:
                print(f"[!] Failed to retrieve results from {engine_name}: HTTP {response.status_code}")
                results_data['failed_engines'].append({
                    'engine': engine_name,
                    'reason': f'HTTP {response.status_code}'
                })
        except Exception as e:
            print(f"[!] Error searching {engine_name} with term '{term}': {e}")
            if not any(fe['engine'] == engine_name for fe in results_data['failed_engines']):
                results_data['failed_engines'].append({
                    'engine': engine_name,
                    'reason': f'Error: {str(e)}'
                })
    
    return all_results

def filter_leak_focused_results(results):
    """
    Filter and score results to prioritize those likely containing leaked data
    """
    filtered_results = []
    
    for result in results:
        # Calculate a relevance score based on keywords in URL or text
        score = 0
        text = result.get('text', '').lower()
        url = result.get('url', '').lower()
        
        # Check for leak-related keywords
        for keyword in ['leak', 'breach', 'dump', 'database', 'credentials', 'password', 
                        'email', 'account', 'hack', 'compromised', 'stolen']:
            if keyword in text:
                score += 2
            if keyword in url:
                score += 1
        
        # Check for file extensions that often contain leaked data
        for ext in ['.txt', '.csv', '.sql', '.xlsx', '.json', '.dump']:
            if ext in url:
                score += 3
        
        # Add the score to the result
        result['relevance_score'] = score
        
        # Keep results with a minimum score or all results if none meet threshold
        if score >= 1:
            filtered_results.append(result)
    
    # If no results met threshold, return all (avoid empty results)
    if not filtered_results and results:
        return results
        
    # Sort by relevance score
    return sorted(filtered_results, key=lambda x: x.get('relevance_score', 0), reverse=True)

def main():
    """
    Main function to handle the dark web search
    """
    parser = argparse.ArgumentParser(description="Search the dark web using Tor")
    parser.add_argument("search_term", help="Term to search for on the dark web")
    parser.add_argument("--output", "-o", default="darkweb_results.json", 
                        help="Output file to save results (default: darkweb_results.json)")
    parser.add_argument("--engines", "-e", nargs="+", 
                        help="Specific search engines to use (default: Ahmia only)")
    parser.add_argument("--all-engines", "-a", action="store_true",
                        help="Try all available engines (may result in connection errors)")
    parser.add_argument("--timeout", "-t", type=int, default=45,
                        help="Connection timeout in seconds (default: 45)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Enable verbose output")
    parser.add_argument("--leak-focused", "-l", action="store_true",
                        help="Focus search on leaked data, credentials and accounts")
    parser.add_argument("--include-leak-sites", "-i", action="store_true",
                        help="Include specialized leak/breach focused sites")
    args = parser.parse_args()
    
    # Check if --all-engines flag is used, and if so, re-enable all engines
    if args.all_engines:
        global SEARCH_ENGINES
        SEARCH_ENGINES = {
            "Torch": "http://torchqsxkllrj2eqaitp5xvcgfeg3g5dr3bm33aoottd4rhvykr7aqid.onion/search?query={}&action=search",
            "Ahmia": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={}",
            "DarkSearch": "http://darksearch777.onion/search?query={}",
            "NotEvil": "http://hss3uro2hsxfogfq.onion/index.php?q={}",
            "Haystack": "http://haystak5njsmn2hqkewecpaxetahtwhsbsa64jom2k22z5afxhnpxfid.onion/?q={}",
            "Kilos": "http://mlyusr6htlxsyc7t2f4z53wdxh3win7q3qpxcrbam6jf3dmua7tnzuyd.onion/search?q={}"
        }
        print("[*] All engines enabled (including potentially non-functioning ones)")
    
    # Enhance search term for leak-focused searches
    search_term = args.search_term
    if args.leak_focused:
        print("[*] Enhancing search term to focus on leaked data and credentials")
        search_term = enhance_search_term(args.search_term, True)
    
    # Check if Tor is running
    try:
        session = requests.session()
        session.proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
        session.get("https://check.torproject.org", timeout=args.timeout)
        print("[+] Successfully connected to Tor network")
    except requests.exceptions.ConnectionError:
        print("[!] Error: Tor proxy is not running. Start the Tor service first.")
        print("    You can start Tor with: service tor start")
        return
    except Exception as e:
        print(f"[!] Error checking Tor connection: {e}")
        print("    Make sure Tor is properly configured and running")
        return
    
    # Initialize results data structure
    results_data = {
        'search_term': args.search_term,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'total_results': 0,
        'engines_searched': 0,
        'successful_engines': [],
        'failed_engines': [],
        'engines': {},
        'leak_focused': args.leak_focused
    }
    
    print(f"[*] Starting dark web search for: {args.search_term}")
    if args.leak_focused:
        print("[*] Search is focused on leaked data, credentials, and accounts")
    print(f"[*] Results will be saved to: {args.output}")
    
    # Set up the Tor session
    session = setup_tor_session()
    engines_searched = 0
    
    # Determine which search engines to use
    engines_to_use = args.engines if args.engines else list(SEARCH_ENGINES.keys())
    
    print(f"[*] Will attempt to search {len(engines_to_use)} engines: {', '.join(engines_to_use)}")
    
    # Search each engine
    for engine_name in engines_to_use:
        if engine_name in SEARCH_ENGINES:
            engines_searched += 1
            results_data['engines_searched'] = engines_searched
            
            print(f"\n[*] Searching on {engine_name}...")
            
            results = search_onion_site(session, search_term, 
                                       SEARCH_ENGINES[engine_name], args.output, engine_name, results_data)
            
            if results > 0:
                if engine_name not in results_data['successful_engines']:
                    results_data['successful_engines'].append(engine_name)
            
            # Get a new Tor identity before searching the next engine
            get_new_tor_identity()
        else:
            print(f"[!] Unknown search engine: {engine_name}")
            print(f"    Available engines: {', '.join(SEARCH_ENGINES.keys())}")
    
    # Add specialized leak sites if requested
    if args.include_leak_sites or args.leak_focused:
        print("\n[*] Searching specialized leak/breach sites...")
        for site_name, url_template in LEAK_SITES.items():
            engines_searched += 1
            results_data['engines_searched'] = engines_searched
            
            print(f"[*] Searching on {site_name}...")
            
            # For leak sites, we use the original search term without enhancements
            results = search_onion_site(session, args.search_term, 
                                       url_template, args.output, site_name, results_data)
            
            if results > 0:
                if site_name not in results_data['successful_engines']:
                    results_data['successful_engines'].append(site_name)
            
            # Get a new Tor identity before searching the next site
            get_new_tor_identity()
    
    # Write results to JSON file
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(results_data, f, indent=4, ensure_ascii=False)
    
    print(f"\n[*] Search complete. Total results: {results_data['total_results']}")
    print(f"[*] Engines searched: {results_data['engines_searched']}")
    print(f"[*] Successful engines: {len(results_data['successful_engines'])}")
    if results_data['successful_engines']:
        print(f"[*] Results found on: {', '.join(results_data['successful_engines'])}")
    print(f"[*] Results saved to: {args.output}")

if __name__ == "__main__":
    main()