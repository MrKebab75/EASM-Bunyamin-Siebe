# DetectWebTechnologies.py

This script detects web technologies used by domains extracted from the `all_subdomains.json` file. It produces a JSON output file with domains and their associated web technologies.

## Features

- Extracts main domains from the "domain" field in all_subdomains.json
- Detects web technologies using multiple methods and combines results:
  - WhatRuns API
  - HTTPS detection with HTTP headers and content analysis
  - HTTP detection with HTTP headers and content analysis
  - WebTech library (if available)
- Compares results from all methods to find the most technologies
- Provides detailed logging and statistics during scanning
- Outputs results in JSON format with detailed technology information
- Includes version detection for discovered technologies

## Input Format

The script expects the input file (all_subdomains.json) to have the following structure:

```json
[
  {
    "domain": "example.com",
    "subdomains_found": 3,
    "results": [
      {
        "subdomain": "www.example.com",
        "ip": "192.168.1.1"
      },
      ...
    ]
  },
  ...
]
```

The script will extract the main domains from the "domain" field.

## Prerequisites

- Python 3.6+
- Required Python packages: `requests`
- Optional: `webtech` package for enhanced detection

## Installation

1. Clone or download this repository
2. Install required dependencies:

```bash
# Basic installation
pip install requests

# For enhanced detection (recommended)
pip install webtech requests
```

## Usage

Run the script with default settings:

```bash
./Scripts/DetectWebTechnologies.py
```

### Command Line Options

- `--input PATH`: Path to input JSON file with domains (default: `foundData/all_subdomains.json`)
- `--output PATH`: Path to output JSON file (default: `foundData/web_technologies.json`)
- `--max-domains N`: Limit scanning to N domains (default: all domains)
- `--verbose`: Enable detailed output during scanning

### Examples

Scan all domains with verbose output:

```bash
./Scripts/DetectWebTechnologies.py --verbose
```

Scan only the first 5 domains:

```bash
./Scripts/DetectWebTechnologies.py --max-domains 5
```

Specify custom input and output files:

```bash
./Scripts/DetectWebTechnologies.py --input custom_domains.json --output results.json
```

## Output Format

The script generates a JSON file with the following structure:

```json
{
  "example.com": [
    {
      "name": "Apache",
      "version": "2.4.41",
      "categories": ["Web Server"],
      "confidence": 90,
      "detection_method": "https"
    },
    {
      "name": "PHP",
      "version": "7.4.3",
      "categories": ["Programming Language"],
      "confidence": 90,
      "detection_method": "whatruns"
    }
  ],
  "another-domain.org": [
    ...
  ]
}
```

Each domain contains an array of detected technologies with:
- Technology name
- Version (when available)
- Categories
- Confidence score (0-100)
- Detection method used (whatruns, https, or http)
- Detection dates (for WhatRuns detections) 