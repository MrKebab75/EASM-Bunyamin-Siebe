# EnhancedCVEScanner.py

This script performs comprehensive CVE vulnerability scanning on domains and IPs from your foundData files. It combines port discovery, vulnerability detection, and detailed reporting in a structured format.

## Features

- Scans domains (from all_subdomains.json) and/or IPs (from subdomains_with_ips.csv)
- Automatic port discovery using nmap service detection
- Targeted vulnerability scanning on specific ports or all discovered ports
- Detailed vulnerability information with severity ratings and CVSS scores
- Comprehensive reporting in both JSON and human-readable text formats
- Customizable scan options via command-line arguments

## Prerequisites

- Python 3.6+
- Nmap (with vulnerability scripts installed)
- Required Python packages: `requests`

## Installation

1. Clone or download this repository
2. Install nmap if not already installed:
   ```bash
   # Ubuntu/Debian
   sudo apt-get install nmap
   
   # macOS
   brew install nmap
   
   # Windows
   # Download and install from https://nmap.org/download.html
   ```

## Usage

Run the script with default settings:

```bash
./Scripts/EnhancedCVEScanner.py
```

By default, this will:
- Scan IPs from `foundData/subdomains_with_ips.csv`
- Discover open ports on each IP and scan them for vulnerabilities
- Save results to `foundData/vulnerability_scan.json` and `foundData/vulnerability_report.txt`

### Command Line Options

```
--input-json PATH        Path to input JSON file with domains (default: foundData/all_subdomains.json)
--input-csv PATH         Path to input CSV file with IPs (default: foundData/subdomains_with_ips.csv)
--output-json PATH       Path to output JSON file (default: foundData/vulnerability_scan.json)
--output-report PATH     Path to output report file (default: foundData/vulnerability_report.txt)
--scan-domains           Scan domains from the JSON file (by default only IPs are scanned)
--scan-ips               Scan IPs from the CSV file (default behavior)
--ports PORTS            Comma-separated list of ports to scan (e.g., '80,443,8080')
--discover-ports         Discover open ports before scanning (default behavior)
--max-targets N          Maximum number of targets to scan
--verbose                Enable verbose output
```

### Examples

Scan only the first 5 IPs with verbose output:

```bash
./Scripts/EnhancedCVEScanner.py --max-targets 5 --verbose
```

Scan both domains and IPs:

```bash
./Scripts/EnhancedCVEScanner.py --scan-domains --scan-ips
```

Scan specific ports only:

```bash
./Scripts/EnhancedCVEScanner.py --ports 80,443,8080,8443
```

Scan domains with custom input and output paths:

```bash
./Scripts/EnhancedCVEScanner.py --scan-domains --input-json custom_domains.json --output-report custom_report.txt
```

## Output Format

### JSON Output

The script generates a JSON file with the following structure:

```json
[
  {
    "ip": "192.168.1.1",
    "timestamp": "2023-07-15 14:30:22",
    "target_name": "example.com",
    "target_type": "domain",
    "ports": {
      "80": {
        "protocol": "tcp",
        "service": "http Apache httpd 2.4.41",
        "vulnerabilities": [
          {
            "id": "CVE-2021-12345",
            "details": "Description of the vulnerability...",
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-12345",
            "cvss": 7.5,
            "severity": "High",
            "port": "80",
            "ip": "192.168.1.1"
          }
        ]
      }
    },
    "vulnerabilities": [
      // Same as above, aggregated from all ports
    ]
  }
]
```

### Text Report

The text report includes:
- Summary statistics (total targets, vulnerabilities by severity)
- Detailed findings for each IP/domain
- Vulnerability information organized by port
- URLs to detailed CVE information
- CVSS scores and severity ratings

## Notes

- The script handles both domain-to-IP resolution and direct IP scanning
- Duplicate targets (same IP from both domain resolution and IP input) are automatically deduplicated
- Scanning may take a considerable amount of time depending on the number of targets and open ports
- The script includes pauses between scans to avoid network overload 