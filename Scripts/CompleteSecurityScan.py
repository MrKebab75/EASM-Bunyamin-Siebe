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
        print(f"[*] Full script path: {script_path}", flush=True)
        print(f"[*] Input file: {input_file}", flush=True)
        print(f"[*] Output directory: {output_dir}", flush=True)
        
        # Get absolute paths
        script_path = os.path.abspath(script_path)
        input_file = os.path.abspath(input_file)
        output_dir = os.path.abspath(output_dir)
        script_dir = os.path.dirname(script_path)  # Directory containing the script
        workspace_dir = os.path.dirname(os.path.dirname(script_path))  # Go up two levels from Scripts/
        
        # Verify script exists
        if not os.path.exists(script_path):
            print(f"[!] Error: Script not found at {script_path}", flush=True)
            return False
            
        # Verify input file exists
        if not os.path.exists(input_file):
            print(f"[!] Error: Input file not found at {input_file}", flush=True)
            return False
            
        # Run the script with stdout and stderr unbuffered
        cmd = ["python3", "-u", script_path, "--input", input_file]
        
        # Special handling for subdom.py - it uses its own output structure
        if os.path.basename(script_path) == "subdom.py":
            try:
                # Create the scan directory if it doesn't exist
                os.makedirs(output_dir, exist_ok=True)
                print(f"[+] Created/verified scan directory: {output_dir}")
                
                # Create a symbolic link in the scan directory pointing to foundData
                scan_found_data = os.path.join(output_dir, "foundData")
                if os.path.exists(scan_found_data):
                    print(f"[*] Removing existing foundData link in scan directory: {scan_found_data}")
                    if os.path.islink(scan_found_data):
                        os.remove(scan_found_data)
                
                # Create symbolic link from scan directory to foundData
                print(f"[*] Creating symbolic link from {scan_found_data} to {output_dir}")
                os.symlink(output_dir, scan_found_data)
                print(f"[+] Created symbolic link from {scan_found_data} to {output_dir}")
                
                # Add output directory parameter for subdom.py
                cmd.extend(["--output-dir", output_dir])
            except Exception as e:
                print(f"[!] Error creating symbolic link: {e}")
                return False
        elif output_dir:
            cmd.extend(["--output-dir", output_dir])
            
        print(f"[*] Executing command: {' '.join(cmd)}", flush=True)
        
        # Change to the script's directory before running
        original_dir = os.getcwd()
        os.chdir(script_dir)
        print(f"[*] Changed working directory to: {script_dir}")
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        print(f"[*] Process started with PID: {process.pid}", flush=True)
        
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
        if error:
            print(f"Error: {error}", flush=True)
            
        return_code = process.returncode
        print(f"[*] Process completed with return code: {return_code}", flush=True)
        
        # Change back to original directory
        os.chdir(original_dir)
        print(f"[*] Changed back to original directory: {original_dir}")
        
        # Clean up symbolic link if it was created
        if os.path.basename(script_path) == "subdom.py":
            try:
                scan_found_data = os.path.join(output_dir, "foundData")
                if os.path.exists(scan_found_data) and os.path.islink(scan_found_data):
                    print(f"[*] Removing symbolic link: {scan_found_data}")
                    os.remove(scan_found_data)
                    print("[+] Removed symbolic link")
            except Exception as e:
                print(f"[!] Error removing symbolic link: {e}")
        
        return return_code == 0
    except Exception as e:
        print(f"Error running {script_path}: {str(e)}", flush=True)
        return False

def main():
    print("[*] Starting CompleteSecurityScan.py", flush=True)
    parser = argparse.ArgumentParser(description='Run a complete security scan on domains')
    parser.add_argument('--input', required=True, help='Input file containing domains')
    parser.add_argument('--output-dir', default='foundData', help='Output directory for results (default: foundData)')
    args = parser.parse_args()
    
    print(f"[*] Arguments parsed:", flush=True)
    print(f"    Input file: {args.input}", flush=True)
    print(f"    Output directory: {args.output_dir}", flush=True)
    
    # Read domains from input file
    print(f"[*] Reading domains from {args.input}")
    try:
        with open(args.input, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
        print(f"[+] Successfully read input file", flush=True)
    except Exception as e:
        print(f"[!] Error reading input file: {e}", flush=True)
        return
    
    print(f"[+] Found {len(domains)} domains to scan")
    
    # Create timestamped directory for this scan
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain = domains[0]  # Get the first domain for the directory name
    scan_dir = os.path.join(args.output_dir, f"scan_{domain}_{timestamp}")
    
    try:
        os.makedirs(scan_dir, exist_ok=True)
        print(f"[+] Created scan directory: {scan_dir}", flush=True)
    except Exception as e:
        print(f"[!] Error creating scan directory: {e}", flush=True)
        return
    
    print(f"[+] Results will be saved in: {scan_dir}")
    
    # List of scripts to run in order
    scripts = [
        "Scripts/subdom.py",
        "Scripts/Certificaat.py",
        "Scripts/DetectWebTechnologies.py",
        "Scripts/Domeingeldigheid.py",
        "Scripts/EnhancedCVEScanner.py",
        "Scripts/Portscan.py"
    ]
    
    print(f"[+] Total number of scans to run: {len(scripts)}")
    
    # Run each script
    for i, script in enumerate(scripts, 1):
        print(f"\n[*] Starting scan {i}/{len(scripts)}: {os.path.basename(script)}")
        
        # Determine input and output for each script
        if os.path.basename(script) == "subdom.py":
            # First script uses the original input file
            input_file = args.input
            output_dir = scan_dir
        else:
            # Other scripts use the all_subdomains.json from the scan directory
            input_file = os.path.join(scan_dir, "all_subdomains.json")
            output_dir = scan_dir
            
        success = run_script(script, input_file, output_dir)
        if not success:
            print(f"[!] Warning: {os.path.basename(script)} did not complete successfully")
    
    print("\n[+] All scans completed!")

if __name__ == "__main__":
    main() 