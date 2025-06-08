# subdom.py

This script performs subdomain enumeration for a list of domains using Amass and Subfinder, resolves their IP addresses, and saves the results in a structured JSON file. It supports resuming scans, skipping unreachable domains, and incremental saving of results.

## Features

- Enumerates subdomains for each domain using Amass and Subfinder
- Resolves IP addresses for all discovered subdomains
- Supports both text and Excel input files (with a 'Domain Name' column)
- Can resume scans or start from a specific domain
- Skips unreachable domains and logs them separately
- Saves all results incrementally to prevent data loss
- Results are saved in JSON format

## Input Format

The script expects an input file with domains, for example:

**Text file (one domain per line):**
```
example.com
sub.example.com
```

**Excel file (Domains.xlsx):**
- Must contain a column named `Domain Name` with one domain per row

## Requirements

- Python 3.6+
- Amass and Subfinder (must be installed and available in PATH)
- Required Python packages: `pandas`, `argparse`, `json`, `os`, `subprocess`, `socket`

## Installation

1. Clone or download this repository
2. Install Python (if needed)
3. Install Amass and Subfinder:
   - Amass: https://github.com/owasp-amass/amass
   - Subfinder: https://github.com/projectdiscovery/subfinder
4. Install required Python packages:

```bash
pip install pandas
```

## Usage

Run the script with default settings:

```bash
python Scripts/subdom.py --input Scripts/domains.txt
```

### Command Line Options

- `--input PATH`: Path to input file (text or Excel)
- `--output-dir PATH`: Directory to save output files (default: `foundData/`)
- `--resume`: Resume scanning from the last domain
- `--start-from DOMAIN`: Start scanning from a specific domain

### Examples

Enumerate subdomains from a text file:

```bash
python Scripts/subdom.py --input Scripts/domains.txt
```

Enumerate subdomains from an Excel file:

```bash
python Scripts/subdom.py --input Scripts/Domains.xlsx
```

Resume a previous scan:

```bash
python Scripts/subdom.py --resume
```

Start scanning from a specific domain:

```bash
python Scripts/subdom.py --start-from example.com
```

## Output Format

The script generates a JSON file with the following structure (all_subdomains.json):

```json
[
  {
    "domain": "example.com",
    "subdomains_found": 3,
    "results": [
      { "subdomain": "www.example.com", "ip": "192.168.1.1" },
      { "subdomain": "mail.example.com", "ip": "192.168.1.2" },
      { "subdomain": "dev.example.com", "ip": null }
    ]
  },
  ...
]
```

Inactive domains are saved in a separate file (inactiveDomains.json):

```json
[
  "offline.example.com",
  ...
]
```

Each entry contains:
- Domain name
- Number of subdomains found
- List of subdomains with their resolved IP addresses (or null if not resolved)
