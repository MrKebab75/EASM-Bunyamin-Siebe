import subprocess
import sys
import json
import os
import time
import argparse
from datetime import datetime

def run_script(script_path, input_file, output_dir):
    """Run a script and return its output."""
    try:
        print(f"\n[*] Running {os.path.basename(script_path)}...", flush=True)
        # Run the script with stdout and stderr unbuffered
        process = subprocess.Popen(
            ["python", "-u", script_path, "--input", input_file, "--output-dir", output_dir],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        # Read output in real-time
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(output.strip(), flush=True)
        
        # Get any remaining output
        remaining_output, error = process.communicate()
        if remaining_output:
            print(remaining_output.strip(), flush=True)
        
        if process.returncode != 0:
            print(f"[!] Error in {os.path.basename(script_path)}: {error}", flush=True)
            return False
            
        return True
    except Exception as e:
        print(f"[!] Error running {os.path.basename(script_path)}: {e}", flush=True)
        return False

def main():
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Complete Security Scan')
    parser.add_argument('--input', help='Input file containing domains (one per line)')
    args = parser.parse_args()

    # Define paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    base_dir = os.path.dirname(script_dir)
    
    # Ensure the input file exists
    if not args.input:
        print("[!] No input file specified")
        sys.exit(1)
        
    if not os.path.exists(args.input):
        print(f"[!] Input file not found: {args.input}")
        sys.exit(1)
    
    # Load domains from input file
    print(f"[*] Reading domains from {args.input}")
    try:
        with open(args.input, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
    except Exception as e:
        print(f"[!] Error reading input file: {e}")
        sys.exit(1)
    
    if not domains:
        print("[!] No domains found in the input file")
        sys.exit(1)
    
    print(f"[+] Found {len(domains)} domains to scan")
    
    # Create timestamped output directory for this scan
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_dir = os.path.join(base_dir, "foundData", f"scan_{domains[0]}_{timestamp}")
    os.makedirs(scan_dir, exist_ok=True)
    
    print(f"[+] Results will be saved in: {scan_dir}")
    
    # List of scripts to run with their output files
    scripts_to_run = [
        {
            "script": "subdom.py",
            "output_files": [
                "all_subdomains.json",
                "activeDomains.json",
                "inactiveDomains.json"
            ]
        },
        {
            "script": "Certificaat.py",
            "output_files": ["certificates.json"]
        },
        {
            "script": "Domeingeldigheid.py",
            "output_files": ["domainLease.json"]
        },
        {
            "script": "DetectWebTechnologies.py",
            "output_files": ["web_technologies.json"]
        },
        {
            "script": "Portscan.py",
            "output_files": ["ports.json"]
        },
        {
            "script": "EnhancedCVEScanner.py",
            "output_files": [
                "vulnerability_scan.json",
                "vulnerability_report.txt"
            ]
        }
    ]
    
    print(f"[+] Total number of scans to run: {len(scripts_to_run)}\n")
    
    # Run each script
    for i, script_info in enumerate(scripts_to_run, 1):
        script = script_info["script"]
        script_path = os.path.join(script_dir, script)
        
        if not os.path.exists(script_path):
            print(f"[!] Script not found: {script}")
            continue
            
        print(f"[*] Starting scan {i}/{len(scripts_to_run)}: {script}")
        try:
            # Create a temporary file for this script
            temp_input = os.path.join(scan_dir, f"temp_input_{i}.txt")
            with open(temp_input, 'w') as f:
                for domain in domains:
                    f.write(f"{domain}\n")
            
            # Run the script with python3
            result = subprocess.run(
                ["python3", script_path, "--input", temp_input],
                capture_output=True,
                text=True
            )
            
            # Print output
            if result.stdout:
                print(result.stdout)
            if result.stderr:
                print(f"[!] Errors from {script}:")
                print(result.stderr)
            
            # Copy output files to scan directory
            for output_file in script_info["output_files"]:
                source_path = os.path.join(base_dir, "foundData", output_file)
                if os.path.exists(source_path):
                    # Copy the file to the scan directory
                    dest_path = os.path.join(scan_dir, output_file)
                    with open(source_path, 'r') as src, open(dest_path, 'w') as dst:
                        dst.write(src.read())
                    print(f"[+] Copied {output_file} to scan directory")
            
            # Clean up temporary file
            os.remove(temp_input)
            
            print(f"[+] Completed scan {i}/{len(scripts_to_run)}: {script}\n")
            
        except Exception as e:
            print(f"[!] Error running {script}: {e}")
            continue
    
    # Create a summary file
    summary_file = os.path.join(scan_dir, "scan_summary.txt")
    try:
        with open(summary_file, 'w') as f:
            f.write(f"Complete Security Scan Summary\n")
            f.write(f"===========================\n\n")
            f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target Domain: {domains[0]}\n")
            f.write(f"Number of Scans: {len(scripts_to_run)}\n\n")
            f.write("Scans Performed:\n")
            for script_info in scripts_to_run:
                f.write(f"- {script_info['script']}\n")
                f.write("  Output files:\n")
                for output_file in script_info["output_files"]:
                    f.write(f"    - {output_file}\n")
            f.write(f"\nResults saved in: {scan_dir}\n")
        print(f"[+] Created summary file: {summary_file}")
    except Exception as e:
        print(f"[!] Error creating summary file: {e}")
    
    print("[+] Complete security scan finished")
    print(f"[+] All results saved in: {scan_dir}")

if __name__ == "__main__":
    main() 