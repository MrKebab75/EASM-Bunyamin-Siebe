from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_file
import subprocess
import json
import os
import pandas as pd
from werkzeug.utils import secure_filename
import uuid
import threading

app = Flask(__name__)
app.secret_key = 'your-secret-key-here'  # Required for flash messages

# Configure upload folder
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
ALLOWED_EXTENSIONS = {'xlsx', 'xls'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Create uploads folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Create a temporary folder for single domain scan outputs
TEMP_OUTPUT_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'temp_outputs')
os.makedirs(TEMP_OUTPUT_FOLDER, exist_ok=True)

# Ensure proper permissions
for folder in [UPLOAD_FOLDER, TEMP_OUTPUT_FOLDER]:
    try:
        os.chmod(folder, 0o755)  # rwxr-xr-x
    except Exception as e:
        print(f"Warning: Could not set permissions for {folder}: {e}")

scripts = {
    "certificaat": "Scripts/Certificaat.py",
    "detect_web_tech": "Scripts/DetectWebTechnologies.py",
    "domeingeldigheid": "Scripts/Domeingeldigheid.py",
    "enhanced_cve": "Scripts/EnhancedCVEScanner.py",
    "portscan": "Scripts/Portscan.py",
    "subdom": "Scripts/subdom.py",
    "complete_scan": "Scripts/CompleteSecurityScan.py"
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def process_excel_file(file_path):
    try:
        df = pd.read_excel(file_path)
        if 'Domain Name' not in df.columns:
            return None, "Excel file must contain a 'Domain Name' column"
        return df['Domain Name'].tolist(), None
    except Exception as e:
        return None, str(e)

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # Debug print all form data
        print("[*] Form data received:")
        for key, value in request.form.items():
            print(f"  {key}: {value}")
            
        script_name = request.form.get("script")
        input_type = request.form.get(f"input_type_{script_name}")
        
        print(f"[*] Processing request for script: {script_name}, input type: {input_type}")
        
        if script_name not in scripts:
            print(f"[!] Invalid script name: {script_name}")
            return redirect(url_for("index"))
            
        domains = []
        
        if input_type == "single":
            domain = request.form.get(f"domain_{script_name}")
            print(f"[*] Received domain input: {domain}")
            if not domain:
                print("[!] No domain provided")
                return redirect(url_for("index"))
            domains = [domain.strip()]
        else:  # Excel file
            file_key = f"file_{script_name}"
            if file_key not in request.files:
                print(f"[!] No file uploaded for {script_name}")
                return redirect(url_for("index"))
                
            file = request.files[file_key]
            if file.filename == '':
                print("[!] No file selected")
                return redirect(url_for("index"))
                
            if not allowed_file(file.filename):
                print(f"[!] Invalid file type: {file.filename}")
                return redirect(url_for("index"))
                
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            domains, error = process_excel_file(file_path)
            if error:
                print(f"[!] Error processing Excel file: {error}")
                return redirect(url_for("index"))
                
            # Clean up the uploaded file
            os.remove(file_path)
        
        if not domains:
            print("[!] No domains to process")
            return redirect(url_for("index"))
            
        print(f"[+] Processing {len(domains)} domains: {domains}")
        
        # Create a temporary file with domains
        temp_file = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_domains.txt')
        try:
            # Ensure the uploads directory exists
            os.makedirs(os.path.dirname(temp_file), exist_ok=True)
            
            with open(temp_file, 'w') as f:
                for domain in domains:
                    f.write(f"{domain}\n")
            print(f"[+] Created temporary file at: {temp_file}")
            
            # Verify the file was created and has content
            if os.path.exists(temp_file):
                print(f"[+] Verified temporary file exists at: {temp_file}")
                print(f"[+] File contents:")
                with open(temp_file, 'r') as f:
                    content = f.read()
                    print(content)
                    if not content.strip():
                        print("[!] Warning: Temporary file is empty")
                        return redirect(url_for("index"))
            else:
                print(f"[!] Temporary file was not created at: {temp_file}")
                return redirect(url_for("index"))
                
        except Exception as e:
            print(f"[!] Error writing to temp file: {e}")
            return redirect(url_for("index"))
        
        try:
            # Create output file
            output_id = str(uuid.uuid4())
            output_file = os.path.join(TEMP_OUTPUT_FOLDER, f"{output_id}.txt")
            
            # Create initial output file
            with open(output_file, 'w') as f:
                f.write(f"Starting {script_name} scan...\n")
            
            print(f"[+] Created output file at: {output_file}")
            
            # Start the background task
            thread = threading.Thread(
                target=update_output_file,
                args=(script_name, temp_file, output_file)
            )
            thread.daemon = True
            thread.start()
            
            print(f"[+] Redirecting to display page for output_id: {output_id}")
            return redirect(url_for('display_output', output_id=output_id))
            
        except Exception as e:
            print(f"[!] Error starting scan: {e}")
            if os.path.exists(temp_file):
                os.remove(temp_file)
            return redirect(url_for("index"))
    
    return render_template("index.html", scripts=scripts)

@app.route("/display-output/<output_id>")
def display_output(output_id):
    print(f"[*] Displaying output for ID: {output_id}")
    output_file = os.path.join(TEMP_OUTPUT_FOLDER, f"{output_id}.txt")
    
    if not os.path.exists(output_file):
        print(f"[!] Output file not found: {output_file}")
        return "Output file not found", 404
    
    try:
        with open(output_file, 'r') as f:
            output = f.read()
        print(f"[+] Successfully read output file")
        return render_template("display_output.html", output=output, output_id=output_id)
    except Exception as e:
        print(f"[!] Error reading output file: {e}")
        return "Error reading output file", 500

@app.route("/update-output/<output_id>")
def update_output(output_id):
    print(f"[*] Updating output for ID: {output_id}")
    output_file = os.path.join(TEMP_OUTPUT_FOLDER, f"{output_id}.txt")
    
    if not os.path.exists(output_file):
        print(f"[!] Output file not found: {output_file}")
        return "Output file not found", 404
    
    try:
        with open(output_file, 'r') as f:
            output = f.read()
        print(f"[+] Successfully read output file for update")
        return output
    except Exception as e:
        print(f"[!] Error reading output file for update: {e}")
        return "Error reading output file", 500

# Add a background task to update the output file
def update_output_file(script_name, input_file, output_file, process=None):
    try:
        print(f"[*] Starting background task for {script_name}")
        print(f"[*] Using input file: {input_file}")
        print(f"[*] Writing output to: {output_file}")
        
        # Create output directory if it doesn't exist
        output_dir = os.path.dirname(output_file)
        os.makedirs(output_dir, exist_ok=True)
        
        # Write initial message
        with open(output_file, 'w') as f:
            f.write(f"Starting {script_name} scan...\n")
            f.flush()
        
        # Determine if this is a complete scan or individual tool
        is_complete_scan = script_name == "complete_scan"
        
        # If process is not provided, create one
        if process is None:
            # Prepare the command
            if is_complete_scan:
                # For complete scan, use foundData as output directory
                cmd = ["python3", "-u", scripts[script_name], "--input", input_file, "--output-dir", "foundData"]
                print(f"[*] Running complete scan with output to foundData directory")
            else:
                # For individual tools, just use the input file
                cmd = ["python3", "-u", scripts[script_name], "--input", input_file]
                print(f"[*] Running individual tool scan")
            
            print(f"[*] Executing command: {' '.join(cmd)}")
            
            # Run the script
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
                print(f"[*] Script output: {output.strip()}")
                with open(output_file, 'a') as f:
                    f.write(output)
                    f.flush()
        
        # Get any remaining output
        remaining_output, error = process.communicate()
        if remaining_output:
            print(f"[*] Remaining output: {remaining_output.strip()}")
            with open(output_file, 'a') as f:
                f.write(remaining_output)
                f.flush()
        if error:
            print(f"[!] Script error: {error}")
            with open(output_file, 'a') as f:
                f.write(f"\nErrors: {error}")
                f.flush()
        
        # Write completion message
        with open(output_file, 'a') as f:
            f.write("\nScan completed.\n")
            f.flush()
            
        print(f"[+] Background task completed for {script_name}")
        
    except Exception as e:
        print(f"[!] Error in background task: {e}")
        try:
            with open(output_file, 'a') as f:
                f.write(f"\nError: {str(e)}")
                f.flush()
        except Exception as write_error:
            print(f"[!] Error writing error message: {write_error}")
    finally:
        # Only clean up the temporary file after the process has completed
        if process and process.poll() is not None:
            if os.path.exists(input_file):
                try:
                    os.remove(input_file)
                    print(f"[+] Cleaned up temporary file: {input_file}")
                except Exception as e:
                    print(f"[!] Error cleaning up temporary file: {e}")

@app.route("/download-output/<output_id>")
def download_output(output_id):
    output_file = os.path.join(TEMP_OUTPUT_FOLDER, f"{output_id}.txt")
    if not os.path.exists(output_file):
        flash("Output file not found", "error")
        return redirect(url_for("index"))
    
    return send_file(output_file, as_attachment=True, download_name="script_output.txt")

@app.route("/cleanup-output/<output_id>")
def cleanup_output(output_id):
    output_file = os.path.join(TEMP_OUTPUT_FOLDER, f"{output_id}.txt")
    if os.path.exists(output_file):
        os.remove(output_file)
    return redirect(url_for("index"))

@app.route("/export-output", methods=["POST"])
def export_output():
    output = request.form.get("output", "")
    if not output:
        flash("No output to export", "error")
        return redirect(url_for("index"))
    
    # Create a text file with the output
    output_file = os.path.join(app.config['UPLOAD_FOLDER'], 'script_output.txt')
    with open(output_file, 'w') as f:
        f.write(output)
    
    return send_file(output_file, as_attachment=True, download_name="script_output.txt")

@app.route("/domain-visualization")
def domain_visualization():
    return render_template("domain_visualization.html")

@app.route("/certificate-visualization")
def certificate_visualization():
    return render_template("certificate_visualization.html")

@app.route("/domain-lease-visualization")
def domain_lease_visualization():
    return render_template("domain_lease_visualization.html")

@app.route("/web-technologies-visualization")
def web_technologies_visualization():
    return render_template("web_technologies_visualization.html")

@app.route("/port-scan-visualization")
def port_scan_visualization():
    return render_template("portscan_visualization.html")

@app.route("/darknet-visualization")
def darknet_visualization():
    return render_template("darknet_visualization.html")

@app.route("/api/domains")
def get_domains():
    try:
        with open("foundData/all_subdomains.json", "r") as f:
            domains_data = json.load(f)
        app.logger.info(f"Loaded {len(domains_data)} domains")
        return jsonify(domains_data)
    except Exception as e:
        app.logger.error(f"Error loading domains data: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/inactive_domains")
def get_inactive_domains():
    try:
        with open("foundData/inactiveDomains.json", "r") as f:
            inactive_domains = json.load(f)
        app.logger.info(f"Loaded {len(inactive_domains)} inactive domains")
        return jsonify(inactive_domains)
    except Exception as e:
        app.logger.error(f"Error loading inactive domains: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/certificates")
def get_certificates():
    try:
        with open("foundData/certificates.json", "r") as f:
            certificates_data = json.load(f)
        app.logger.info(f"Loaded {len(certificates_data)} certificates")
        return jsonify(certificates_data)
    except Exception as e:
        app.logger.error(f"Error loading certificates data: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/domain_lease")
def get_domain_lease():
    try:
        with open("foundData/domainLease.json", "r") as f:
            domain_lease_data = json.load(f)
        app.logger.info(f"Loaded {len(domain_lease_data)} domain leases")
        return jsonify(domain_lease_data)
    except Exception as e:
        app.logger.error(f"Error loading domain lease data: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/web_technologies")
def get_web_technologies():
    try:
        with open("foundData/web_technologies.json", "r") as f:
            web_technologies_data = json.load(f)
        app.logger.info(f"Loaded {len(web_technologies_data)} domains with web technologies")
        return jsonify(web_technologies_data)
    except Exception as e:
        app.logger.error(f"Error loading web technologies data: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/port_services")
def get_port_services():
    try:
        with open("foundData/port_services_scan.json", "r") as f:
            port_services_data = json.load(f)
        app.logger.info(f"Loaded {len(port_services_data)} IP addresses with port services")
        return jsonify(port_services_data)
    except Exception as e:
        app.logger.error(f"Error loading port services data: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/api/darknet")
def get_darknet_data():
    try:
        with open("foundData/darknet.json", "r") as f:
            darknet_data = json.load(f)
        app.logger.info(f"Loaded darknet data with {darknet_data.get('total_results', 0)} results")
        return jsonify(darknet_data)
    except Exception as e:
        app.logger.error(f"Error loading darknet data: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route("/run-script/<script_name>", methods=["POST"])
def run_script(script_name):
    if script_name not in scripts:
        return redirect(url_for("index"))
    
    # Create a temporary file with domains
    temp_file = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_domains.txt')
    with open(temp_file, 'w') as f:
        for domain in request.form.getlist('domains'):
            f.write(f"{domain}\n")
    
    try:
        # Create output file
        output_id = str(uuid.uuid4())
        output_file = os.path.join(TEMP_OUTPUT_FOLDER, f"{output_id}.txt")
        
        # Start the background task
        thread = threading.Thread(
            target=update_output_file,
            args=(script_name, temp_file, output_file)
        )
        thread.daemon = True
        thread.start()
        
        # Redirect to display page immediately
        return redirect(url_for('display_output', output_id=output_id))
    except Exception as e:
        # Clean up the temporary file if there's an error
        if os.path.exists(temp_file):
            os.remove(temp_file)
        return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
