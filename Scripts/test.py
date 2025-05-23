


import requests
from bs4 import BeautifulSoup
import re
import json

def clean_js_object(js_obj_str):
    # Remove JS comments (optional)
    js_obj_str = re.sub(r'//.*?\n|/\*.*?\*/', '', js_obj_str, flags=re.DOTALL)

    # Replace JS literals with JSON-compatible ones
    js_obj_str = js_obj_str.replace("undefined", "null")
    js_obj_str = js_obj_str.replace("'", '"')

    # Ensure object keys are quoted (naive but effective for known cases)
    js_obj_str = re.sub(r'([{,])(\s*)([a-zA-Z0-9_]+)\s*:', r'\1"\3":', js_obj_str)

    # Remove trailing commas in objects and arrays
    js_obj_str = re.sub(r',(\s*[}\]])', r'\1', js_obj_str)

    return js_obj_str

def extract_var_s(domain):
    url = f"https://www.whatruns.com/website/{domain}"
    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()

        soup = BeautifulSoup(response.text, 'html.parser')
        scripts = soup.find_all('script')

        for script in scripts:
            if script.string and "var s=" in script.string:
                script_text = script.string
                start_idx = script_text.find("var s=")
                script_slice = script_text[start_idx + len("var s="):]

                brace_count = 0
                object_start = None
                object_end = None

                for i, char in enumerate(script_slice):
                    if char == '{':
                        if brace_count == 0:
                            object_start = i
                        brace_count += 1
                    elif char == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            object_end = i
                            break

                if object_start is not None and object_end is not None:
                    js_object_str = script_slice[object_start:object_end+1]
                    cleaned = clean_js_object(js_object_str)

                    try:
                        parsed = json.loads(cleaned)
                        print("🎉 Successfully parsed JSON:")
                        print(json.dumps(parsed, indent=2))
                        return parsed
                    except json.JSONDecodeError as e:
                        print("❌ JSON decoding failed.")
                        print("Cleaned JS string:")
                        print(cleaned)
                        return None

        print("❌ Could not find `var s`.")
        return None

    except requests.RequestException as e:
        print(f"❌ Request error: {e}")
        return None

if __name__ == "__main__":
    domain_input = input("Enter a domain name (e.g., example.com): ")
    extract_var_s(domain_input)
