# Certificaat.py

This script checks SSL certificates of domains (and subdomains) and saves the results in a JSON file. It provides information about validity, expiration date, issuer, subject, alternative names, and more.

## Features

- Checks SSL certificates of specified domains and subdomains
- Supports both text and JSON input files
- Detects expired or soon-to-expire certificates
- Provides detailed information: issuer, subject, validity, alternative names (SANs), version, serial number
- Logs errors such as timeouts, DNS errors, and SSL errors
- Saves results in JSON format
- Rate limiting to avoid overwhelming servers

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
    "results": [
      { "subdomain": "www.example.com" }
    ]
  }
]
```

## Requirements

- Python 3.6+
- Required Python packages: `ssl`, `socket`, `argparse`, `json`, `os`

## Installation

1. Clone or download this repository
2. Install Python (if needed)
3. (Optional) Create a virtual environment

## Usage

Run the script with default settings:

```bash
python Scripts/Certificaat.py --input Scripts/domains.txt
```

### Command Line Options

- `--input PATH`: Path to input file (required, text or JSON)
- `--output-dir PATH`: Directory to save the output file (default: `foundData/`)

### Examples

Check domains from a text file:

```bash
python Scripts/Certificaat.py --input Scripts/domains.txt
```

Check domains from a JSON file and save to a custom directory:

```bash
python Scripts/Certificaat.py --input foundData/all_subdomains.json --output-dir results/
```

## Output Format

The script generates a JSON file with the following structure:

```json
[
  {
    "domain": "example.com",
    "status": "valid",
    "issuer": "Let's Encrypt",
    "subject": "example.com",
    "valid_from": "2025-01-01 12:00:00",
    "valid_until": "2025-04-01 12:00:00",
    "days_remaining": 90,
    "expired": false,
    "alt_names": ["example.com", "www.example.com"],
    "version": 3,
    "serial_number": "1234567890"
  },
  {
    "domain": "expired.example.com",
    "status": "error",
    "error_type": "ssl_error",
    "message": "certificate has expired"
  }
]
```

Each entry contains:
- Domain name
- Status (`valid` or `error`)
- Certificate details (if valid)
- Error message (if applicable)
