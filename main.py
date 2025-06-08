from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, send_file
import subprocess
import json
import os
import pandas as pd
from werkzeug.utils import secure_filename
import uuid
import threading
import zipfile
import io
from datetime import datetime

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
        print("\n[*] ===== FORM SUBMISSION DEBUG ===== ")
        print("[*] Form data received:")
        for key, value in request.form.items():
            print(f"  {key}: {value}")
            
        # Debug print all files
        print("\n[*] Files received:")
        for key, file in request.files.items():
            print(f"  {key}: {file.filename}")
            
        script_name = request.form.get("script")
        print(f"\n[*] Script name: {script_name}")
        
        input_type = request.form.get(f"input_type_{script_name}")
        print(f"[*] Input type: {input_type}")
        
        if script_name not in scripts:
            print(f"[!] Invalid script name: {script_name}")
            return redirect(url_for("index"))
            
        domains = []
        
        if input_type == "single":
            domain = request.form.get(f"domain_{script_name}")
            print(f"[*] Received domain input: {domain}")
            if not domain:
                print("[!] No domain provided")
                flash("Please enter a domain", "error")
                return redirect(url_for("index"))
            domains = [domain.strip()]
        elif input_type == "file" or input_type == "excel":  # Excel file
            print("\n[*] Processing Excel file upload")
            file_key = f"file_{script_name}"
            print(f"[*] Looking for file with key: {file_key}")
            print(f"[*] Available files in request: {list(request.files.keys())}")
            
            if file_key not in request.files:
                print(f"[!] No file uploaded for {script_name}")
                print(f"[!] Available files: {list(request.files.keys())}")
                flash("Please select an Excel file", "error")
                return redirect(url_for("index"))
                
            file = request.files[file_key]
            print(f"[*] File object: {file}")
            print(f"[*] File name: {file.filename}")
            
            if file.filename == '':
                print("[!] No file selected")
                flash("Please select an Excel file", "error")
                return redirect(url_for("index"))
                
            if not allowed_file(file.filename):
                print(f"[!] Invalid file type: {file.filename}")
                flash("Invalid file type. Please upload an Excel file (.xlsx or .xls)", "error")
                return redirect(url_for("index"))
                
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            print(f"[*] Saving file to: {file_path}")
            
            try:
                file.save(file_path)
                print(f"[+] File saved successfully")
                
                print(f"[*] Processing Excel file: {file_path}")
                domains, error = process_excel_file(file_path)
                if error:
                    print(f"[!] Error processing Excel file: {error}")
                    flash(f"Error processing Excel file: {error}", "error")
                    return redirect(url_for("index"))
                    
                print(f"[+] Successfully processed Excel file. Found {len(domains)} domains")
                
                # Clean up the uploaded file
                os.remove(file_path)
                print(f"[+] Cleaned up temporary file: {file_path}")
                
            except Exception as e:
                print(f"[!] Error handling file upload: {str(e)}")
                flash(f"Error processing file: {str(e)}", "error")
                return redirect(url_for("index"))
        
        if not domains:
            print("[!] No domains to process")
            flash("No domains found to process", "error")
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
                        flash("No valid domains found in the input", "error")
                        return redirect(url_for("index"))
            else:
                print(f"[!] Temporary file was not created at: {temp_file}")
                flash("Error creating temporary file", "error")
                return redirect(url_for("index"))
                
        except Exception as e:
            print(f"[!] Error writing to temp file: {e}")
            flash(f"Error processing domains: {str(e)}", "error")
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
            flash(f"Error starting scan: {str(e)}", "error")
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
        
        # Read domains from input file
        with open(input_file, 'r') as f:
            domains = [line.strip() for line in f if line.strip()]
        
        total_domains = len(domains)
        print(f"[*] Processing {total_domains} domains")
        
        # Process each domain
        for index, domain in enumerate(domains, 1):
            print(f"[*] Processing domain {index}/{total_domains}: {domain}")
            
            # Create a temporary file for this domain
            temp_domain_file = os.path.join(app.config['UPLOAD_FOLDER'], f'temp_domain_{index}.txt')
            with open(temp_domain_file, 'w') as f:
                f.write(f"{domain}\n")
            
            try:
                # Prepare the command
                if is_complete_scan:
                    # For complete scan, use foundData as output directory
                    cmd = ["python3", "-u", scripts[script_name], "--input", temp_domain_file, "--output-dir", "foundData"]
                    print(f"[*] Running complete scan for domain {domain}")
                else:
                    # For individual tools, just use the input file
                    cmd = ["python3", "-u", scripts[script_name], "--input", temp_domain_file]
                    print(f"[*] Running individual tool scan for domain {domain}")
                
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
                
                # Read output in real-time
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        print(f"[*] Script output for {domain}: {output.strip()}")
                        with open(output_file, 'a') as f:
                            f.write(f"[Domain {index}/{total_domains}: {domain}] {output}")
                            f.flush()
                
                # Get any remaining output
                remaining_output, error = process.communicate()
                if remaining_output:
                    print(f"[*] Remaining output for {domain}: {remaining_output.strip()}")
                    with open(output_file, 'a') as f:
                        f.write(f"[Domain {index}/{total_domains}: {domain}] {remaining_output}")
                        f.flush()
                if error:
                    print(f"[!] Script error for {domain}: {error}")
                    with open(output_file, 'a') as f:
                        f.write(f"[Domain {index}/{total_domains}: {domain}] Errors: {error}")
                        f.flush()
                
            except Exception as e:
                print(f"[!] Error processing domain {domain}: {e}")
                with open(output_file, 'a') as f:
                    f.write(f"[Domain {index}/{total_domains}: {domain}] Error: {str(e)}\n")
                    f.flush()
            finally:
                # Clean up temporary domain file
                if os.path.exists(temp_domain_file):
                    os.remove(temp_domain_file)
        
        # Write completion message
        with open(output_file, 'a') as f:
            f.write("\nAll domains processed. Scan completed.\n")
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
        # Clean up the original input file
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

@app.route("/scan-data-visualization")
def scan_data_visualization():
    return render_template('scan_data_visualization.html')

@app.route('/scan-analysis/<scan_folder>')
def scan_analysis(scan_folder):
    # Verify the scan folder exists
    scan_path = os.path.join('foundData', scan_folder)
    if not os.path.exists(scan_path):
        return "Scan folder not found", 404
    return render_template('scan_analysis.html', scan_folder=scan_folder)

@app.route("/api/scan-data")
def get_scan_data():
    scan_data = {}
    found_data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'foundData')
    
    if os.path.exists(found_data_dir):
        for scan_folder in os.listdir(found_data_dir):
            if scan_folder.startswith('scan_'):
                scan_path = os.path.join(found_data_dir, scan_folder)
                if os.path.isdir(scan_path):
                    scan_data[scan_folder] = {}
                    for file in os.listdir(scan_path):
                        if file.endswith('.json'):
                            file_path = os.path.join(scan_path, file)
                            try:
                                with open(file_path, 'r') as f:
                                    scan_data[scan_folder][file] = json.load(f)
                            except Exception as e:
                                scan_data[scan_folder][file] = {"error": str(e)}
    
    return jsonify(scan_data)

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

@app.route("/api/scan-data/<scan_folder>")
def get_scan_folder_data(scan_folder):
    scan_data = {}
    found_data_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'foundData')
    scan_path = os.path.join(found_data_dir, scan_folder)
    
    if os.path.exists(scan_path) and os.path.isdir(scan_path):
        for file in os.listdir(scan_path):
            if file.endswith('.json'):
                file_path = os.path.join(scan_path, file)
                try:
                    with open(file_path, 'r') as f:
                        scan_data[file] = json.load(f)
                except Exception as e:
                    scan_data[file] = {"error": str(e)}
    
    return jsonify(scan_data)

@app.route('/api/scan-data/<scan_folder>/<filename>')
def get_scan_file(scan_folder, filename):
    try:
        file_path = os.path.join('foundData', scan_folder, filename)
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        with open(file_path, 'r') as f:
            data = json.load(f)
        return jsonify(data)
    except FileNotFoundError:
        return jsonify({'error': 'File not found'}), 404
    except json.JSONDecodeError:
        return jsonify({'error': 'Invalid JSON file'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/download-scan-folder/<scan_folder>')
def download_scan_folder(scan_folder):
    scan_folder_path = os.path.join('foundData', scan_folder)

    if not os.path.isdir(scan_folder_path):
        flash('Scan folder not found!', 'error')
        return redirect(url_for('scan_data_visualization'))

    # Create a BytesIO object to hold the zip file in memory
    memory_file = io.BytesIO()

    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(scan_folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                # Ensure the path inside the zip is relative to the scan_folder
                arcname = os.path.relpath(file_path, scan_folder_path)
                zf.write(file_path, os.path.join(scan_folder, arcname)) # Include scan_folder in zip path

    memory_file.seek(0)

    return send_file(memory_file,
                     mimetype='application/zip',
                     as_attachment=True,
                     download_name=f'{scan_folder}.zip')

@app.route("/api/high-risk-vulnerabilities")
def get_high_risk_vulnerabilities():
    found_data_folder = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'foundData')
    
    # Dictionary to store the latest scan folder for each domain with high-risk vulnerabilities
    domain_to_latest_high_risk_scan = {}

    for scan_folder_name in os.listdir(found_data_folder):
        scan_folder_path = os.path.join(found_data_folder, scan_folder_name)
        
        if os.path.isdir(scan_folder_path) and scan_folder_name.startswith('scan_'):
            # Extract timestamp from scan folder name (e.g., scan_domain.com_YYYYMMDD_HHMMSS)
            try:
                timestamp_str = scan_folder_name.split('_')[-2] + scan_folder_name.split('_')[-1]
                current_scan_timestamp = datetime.strptime(timestamp_str, '%Y%m%d%H%M%S')
            except ValueError:
                print(f"Could not parse timestamp from folder: {scan_folder_name}")
                continue

            has_high_risk_vuln_in_folder = False # Flag for current folder
            
            # Process web_technologies.json
            web_tech_path = os.path.join(scan_folder_path, 'web_technologies.json')
            if os.path.exists(web_tech_path):
                try:
                    with open(web_tech_path, 'r') as f:
                        web_tech_data = json.load(f)
                    for domain_name, domain_data in web_tech_data.items():
                        if domain_data.get('status') == 'success' and 'technologies' in domain_data:
                            for tech in domain_data['technologies']:
                                if 'vulnerabilities' in tech and isinstance(tech['vulnerabilities'], list):
                                    for vuln in tech['vulnerabilities']:
                                        severity = vuln.get('severity', '').lower()
                                        if severity == 'high' or severity == 'critical':
                                            has_high_risk_vuln_in_folder = True
                                            # Update if this scan folder is newer or if the domain is not yet recorded
                                            if domain_name not in domain_to_latest_high_risk_scan or \
                                               current_scan_timestamp > domain_to_latest_high_risk_scan[domain_name]['timestamp']:
                                                domain_to_latest_high_risk_scan[domain_name] = {
                                                    'timestamp': current_scan_timestamp,
                                                    'scan_folder': scan_folder_name,
                                                    'domain': domain_name
                                                }
                except Exception as e:
                    print(f"Error reading {web_tech_path}: {e}")

            # Process cve_scan_results.json
            cve_scan_path = os.path.join(scan_folder_path, 'cve_scan_results.json')
            if os.path.exists(cve_scan_path):
                try:
                    with open(cve_scan_path, 'r') as f:
                        cve_data = json.load(f)
                    if isinstance(cve_data, list):
                        for entry in cve_data:
                            domain_name = entry.get('domain')
                            if domain_name and (
                                ('vulnerabilities' in entry and isinstance(entry['vulnerabilities'], list)) or
                                ('ports' in entry and isinstance(entry['ports'], dict))
                            ):
                                vulnerabilities_in_entry = []
                                if 'vulnerabilities' in entry:
                                    vulnerabilities_in_entry.extend(entry['vulnerabilities'])
                                if 'ports' in entry:
                                    for port_data in entry['ports'].values():
                                        if 'vulnerabilities' in port_data and isinstance(port_data['vulnerabilities'], list):
                                            vulnerabilities_in_entry.extend(port_data['vulnerabilities'])

                                for vuln in vulnerabilities_in_entry:
                                    severity = vuln.get('severity', '').lower()
                                    if severity == 'high' or severity == 'critical':
                                        has_high_risk_vuln_in_folder = True
                                        # Update if this scan folder is newer or if the domain is not yet recorded
                                        if domain_name not in domain_to_latest_high_risk_scan or \
                                           current_scan_timestamp > domain_to_latest_high_risk_scan[domain_name]['timestamp']:
                                            domain_to_latest_high_risk_scan[domain_name] = {
                                                'timestamp': current_scan_timestamp,
                                                'scan_folder': scan_folder_name,
                                                'domain': domain_name
                                            }
                except Exception as e:
                    print(f"Error reading {cve_scan_path}: {e}")

    # Convert the dictionary values to a list, containing only domain and scan_folder
    high_risk_domains_list = []
    for domain_info in domain_to_latest_high_risk_scan.values():
        high_risk_domains_list.append({
            'domain': domain_info['domain'],
            'scan_folder': domain_info['scan_folder']
        })

    return jsonify({'high_risk_domains': high_risk_domains_list})

if __name__ == "__main__":
    app.run(debug=True)
