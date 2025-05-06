import os
import json
from flask import Flask, render_template, jsonify, send_from_directory

app = Flask(__name__, static_folder='static', template_folder='templates')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/certificate_visualization')
def certificate_visualization():
    return render_template('certificate_visualization.html')

@app.route('/domain_visualization')
def domain_visualization():
    return render_template('domain_visualization.html')

@app.route('/domain_lease_visualization')
def domain_lease_visualization():
    return render_template('domain_lease_visualization.html')

@app.route('/web_technologies_visualization')
def web_technologies_visualization():
    return render_template('web_technologies_visualization.html')

@app.route('/api/certificates')
def get_certificates():
    try:
        # Load certificate data from the foundData folder
        base_dir = os.path.dirname(os.path.abspath(__file__))
        certificates_file = os.path.join(base_dir, 'foundData', 'certificates.json')
        
        if not os.path.exists(certificates_file):
            return jsonify({"error": f"Certificates file not found at {certificates_file}"}), 404
        
        with open(certificates_file, 'r') as f:
            certificates = json.load(f)
        
        return jsonify(certificates)
    except Exception as e:
        app.logger.error(f"Error loading certificates: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/foundData/<path:filename>')
def serve_found_data(filename):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return send_from_directory(os.path.join(base_dir, 'foundData'), filename)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 