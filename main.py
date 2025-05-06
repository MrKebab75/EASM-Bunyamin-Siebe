from flask import Flask, render_template, request, redirect, url_for, jsonify
import subprocess
import json
import os

app = Flask(__name__)

scripts = {
    "1": "Scripts/Certificaat.py",
    "2": "Scripts/Domeingeldigheid.py",
    "3": "Scripts/subdom.py",
    "4": "Scripts/WhatRunsScan.py",
    "5": "Scripts/GevoeligeFiles.py",
}

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        script_key = request.form.get("script")
        if script_key in scripts:
            subprocess.run(["python", scripts[script_key]])
            return redirect(url_for("index"))
    return render_template("index.html", scripts=scripts)

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

if __name__ == "__main__":
    app.run(debug=True)
