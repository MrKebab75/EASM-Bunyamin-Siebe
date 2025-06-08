# Domeingeldigheid.py

This script checks the validity and expiration date of domain names using WHOIS and saves the results in a JSON file. It provides information about the status, registrar, creation date, expiration date, nameservers, and more.

## Features

- Checks the lease/expiration date of domains via WHOIS
- Supports text and JSON input files (including subdomains)
- Detects expired, valid, and unknown domains
- Provides detailed information: registrar, whois server, creation date, expiration date, last update, nameservers, registrant
- Logs errors and saves them in the output
- Saves results in JSON format

## Input Format

The script expects an input file with domains, for example:

**Text file (one domain per line):**
```
example.com
sub.example.com
```

**JSON file (like all_subdomains.json):**
```json
[
  {
    "domain": "example.com",
    "subdomains": [
      { "name": "www.example.com" }
    ]
  }
]
```

## Requirements

- Python 3.6+
- Required Python packages: `whois`, `pandas`, `argparse`, `json`, `os`

## Installation

1. Clone or download this repository
2. Install the required packages:

```bash
pip install python-whois pandas
```

## Usage

Run the script with default settings:

```bash
python Scripts/Domeingeldigheid.py --input Scripts/domains.txt
```

### Command Line Options

- `--input PATH`: Path to input file (required, text or JSON)
- `--output-dir PATH`: Directory to save the output file (default: `foundData/`)

### Examples

Check domains from a text file:

```bash
python Scripts/Domeingeldigheid.py --input Scripts/domains.txt
```

Check domains from a JSON file and save to a custom directory:

```bash
python Scripts/Domeingeldigheid.py --input foundData/all_subdomains.json --output-dir results/
```

## Output Formaat

The script generates a JSON file with the following structure:

```json
[
  {
    "domain": "example.com",
    "status": "valid",
    "registrar": "Registrar BV",
    "whois_server": "whois.example.com",
    "creation_date": "2020-01-01",
    "expiration_date": "2026-01-01",
    "last_updated": "2025-01-01",
    "days_remaining": 200,
    "name_servers": ["ns1.example.com", "ns2.example.com"],
    "registrant": "John Doe"
  },
  {
    "domain": "expired.example.com",
    "status": "expired",
    "days_remaining": -10
  },
  {
    "domain": "error.example.com",
    "status": "error",
    "error_message": "No WHOIS server found"
  }
]
```

Each entry contains:
- Domain name
- Status (`valid`, `expired`, `unknown`, or `error`)
- Domain and lease details (if available)
- Error message (if applicable)
