# Portscan.py

This script performs a port scan on a list of domains or subdomains using nmap, and saves the results in a structured JSON file. It checks which domains are reachable, scans open ports, and provides service and version information for each port.

## Features

- Scans domains and subdomains for open ports using nmap
- Service and version detection for each open port
- Supports both text and JSON input files (with subdomains)
- Checks if domains are reachable before scanning
- Adds common port descriptions for easy interpretation
- Handles unreachable domains and logs their status
- Saves results incrementally to prevent data loss
- Results are saved in JSON format

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
- nmap (must be installed and available in PATH)
- Required Python packages: `argparse`, `json`, `os`, `re`, `subprocess`, `socket`, `datetime`, `time`

## Installation

1. Clone or download this repository
2. Install Python (if needed)
3. Install nmap:
   - Windows: Download from https://nmap.org/download.html
   - Linux: `sudo apt install nmap`
4. (Optional) Create a virtual environment

## Usage

Run the script with default settings:

```bash
python Scripts/Portscan.py --input Scripts/domains.txt
```

### Command Line Options

- `--input PATH`: Path to input file (required, text or JSON)
- `--output-dir PATH`: Directory to save the output file (default: `foundData/`)

### Examples

Scan domains from a text file:

```bash
python Scripts/Portscan.py --input Scripts/domains.txt
```

Scan domains from a JSON file and save to a custom directory:

```bash
python Scripts/Portscan.py --input foundData/all_subdomains.json --output-dir results/
```

## Output Format

The script generates a JSON file with the following structure:

```json
[
  {
    "domain": "example.com",
    "timestamp": "2025-06-08 12:00:00",
    "status": "completed",
    "host_status": "up",
    "ports": [
      {
        "port": 80,
        "protocol": "tcp",
        "state": "open",
        "service": "http",
        "version": "Apache httpd 2.4.41",
        "description": "HTTP - Hypertext Transfer Protocol"
      },
      ...
    ],
    "scan_time": 2.34
  },
  {
    "domain": "offline.example.com",
    "timestamp": "2025-06-08 12:01:00",
    "status": "completed",
    "host_status": "down",
    "ports": []
  }
]
```

Each entry contains:
- Domain name
- Timestamp
- Status (`completed`, `timeout`, or `error`)
- Host status (`up` or `down`)
- List of open ports with protocol, state, service, version, and description
- Scan time (if available)
- Error message (if applicable)
