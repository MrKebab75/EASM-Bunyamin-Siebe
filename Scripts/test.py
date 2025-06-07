# import requests
# from bs4 import BeautifulSoup
# import re
# import json

# def clean_js_object(js_obj_str):
#     # Remove JS comments (optional)
#     js_obj_str = re.sub(r'//.*?\n|/\*.*?\*/', '', js_obj_str, flags=re.DOTALL)

#     # Replace JS literals with JSON-compatible ones
#     js_obj_str = js_obj_str.replace("undefined", "null")
#     js_obj_str = js_obj_str.replace("'", '"')

#     # Ensure object keys are quoted (naive but effective for known cases)
#     js_obj_str = re.sub(r'([{,])(\s*)([a-zA-Z0-9_]+)\s*:', r'\1"\3":', js_obj_str)

#     # Remove trailing commas in objects and arrays
#     js_obj_str = re.sub(r',(\s*[}\]])', r'\1', js_obj_str)

#     return js_obj_str

# def extract_var_s(domain):
#     url = f"https://www.whatruns.com/website/{domain}"
#     headers = {
#         "User-Agent": "Mozilla/5.0"
#     }

#     try:
#         response = requests.get(url, headers=headers)
#         response.raise_for_status()

#         soup = BeautifulSoup(response.text, 'html.parser')
#         scripts = soup.find_all('script')

#         for script in scripts:
#             if script.string and "var s=" in script.string:
#                 script_text = script.string
#                 start_idx = script_text.find("var s=")
#                 script_slice = script_text[start_idx + len("var s="):]

#                 brace_count = 0
#                 object_start = None
#                 object_end = None

#                 for i, char in enumerate(script_slice):
#                     if char == '{':
#                         if brace_count == 0:
#                             object_start = i
#                         brace_count += 1
#                     elif char == '}':
#                         brace_count -= 1
#                         if brace_count == 0:
#                             object_end = i
#                             break

#                 if object_start is not None and object_end is not None:
#                     js_object_str = script_slice[object_start:object_end+1]
#                     cleaned = clean_js_object(js_object_str)

#                     try:
#                         parsed = json.loads(cleaned)
#                         print("🎉 Successfully parsed JSON:")
#                         print(json.dumps(parsed, indent=2))
#                         return parsed
#                     except json.JSONDecodeError as e:
#                         print("❌ JSON decoding failed.")
#                         print("Cleaned JS string:")
#                         print(cleaned)
#                         return None

#         print("❌ Could not find `var s`.")
#         return None

#     except requests.RequestException as e:
#         print(f"❌ Request error: {e}")
#         return None

# if __name__ == "__main__":
#     domain_input = input("Enter a domain name (e.g., example.com): ")
#     extract_var_s(domain_input)

import sys
import json
import requests
from datetime import datetime
from tabulate import tabulate
import urllib.parse

def get_technologies(domain):
    url = "https://www.whatruns.com/api/v1/get_site_apps"
    
    # Format data exactly like the working version
    data = {
        "data": {
            "hostname": domain,
            "url": domain,
            "rawhostname": domain
        }
    }
    
    # Use urllib.parse for proper encoding
    import urllib.parse
    data_str = urllib.parse.urlencode({k: json.dumps(v) for k, v in data.items()})
    data_str = data_str.replace('+', '')
    
    # Keep headers simple like in the working version
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Origin': 'https://www.whatruns.com',
        'Referer': 'https://www.whatruns.com/',
        'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120"',
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': '"Windows"',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin'
    }
    
    print(f"Sending request to {url} with data: {data_str}")
    
    response = requests.post(url, data=data_str, headers=headers)
    
    if response.status_code != 200:
        print("Error:", response.status_code, response.text)
        return []
    
    print(f"Response received: {len(response.content)} bytes")
    
    # Add debug output
    print(f"Response keys: {list(json.loads(response.content).keys())}")
    
    # Update the processing section in get_technologies to handle the timestamp key format
    try:
        loaded = json.loads(response.content)
        if 'apps' not in loaded:
            print("No 'apps' key in response")
            print(f"Response preview: {str(loaded)[:200]}...")
            return []
            
        # Print the actual content of 'apps' to see what we're dealing with
        print(f"Apps content type: {type(loaded['apps'])}")
        print(f"Apps preview: {str(loaded['apps'])[:200]}...")
        
        # Try direct JSON parsing instead of ast.literal_eval
        if isinstance(loaded['apps'], str):
            try:
                apps = json.loads(loaded['apps'])
            except json.JSONDecodeError:
                print("Could not parse apps as JSON string, trying to process as is")
                apps = loaded['apps']
        else:
            # It's already a dict/list, use it directly
            apps = loaded['apps']
        
        # Continue processing based on the structure
        if isinstance(apps, dict):
            entries = []
            # Process according to the structure we find
            print(f"Apps keys: {list(apps.keys())}")
            
            # Handle timestamp key format (the new format we're seeing)
            for timestamp_key in apps.keys():
                categories_dict = apps[timestamp_key]  # This is a dict of categories
                
                # Now process each category
                for category, tech_items in categories_dict.items():
                    for item in tech_items:
                        # Extract datetime values if available
                        detected_time = None
                        latest_detected_time = None
                        
                        if 'detectedTime' in item:
                            try:
                                # Handle epoch timestamp (milliseconds)
                                detected_time = datetime.fromtimestamp(int(item['detectedTime'])/1000)
                            except (ValueError, TypeError):
                                pass
                        
                        if 'latestDetectedTime' in item:
                            try:
                                # Handle epoch timestamp (milliseconds)
                                latest_detected_time = datetime.fromtimestamp(int(item['latestDetectedTime'])/1000)
                            except (ValueError, TypeError):
                                pass
                        
                        # Get version if available
                        version = item.get('version', 'N/A')
                        
                        # Create entry
                        entry = {
                            'Type': category,
                            'Name': item.get('name', 'Unknown'),
                            'Version': version,
                            'Detected': detected_time.strftime('%Y-%m-%d') if detected_time else 'N/A',
                            'Last Detected': latest_detected_time.strftime('%Y-%m-%d') if latest_detected_time else 'N/A',
                            'Source URL': item.get('sourceUrl', 'N/A')
                        }
                        
                        entries.append(entry)
                        print(f"Added entry: {item.get('name')} {version}")
            
            return entries
        else:
            print(f"Unexpected apps structure: {type(apps)}")
            return []
    except Exception as e:
        print(f"Error processing response: {e}")
        import traceback
        traceback.print_exc()
        return []

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python detect_tech.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    results = get_technologies(domain)

    if results:
        print(tabulate(results, headers='keys'))
    else:
        print("No technologies detected or error occurred.")

