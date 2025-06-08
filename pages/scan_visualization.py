import streamlit as st
import json
import os
from pathlib import Path

# Set page config
st.set_page_config(
    page_title="Scan Visualization",
    page_icon="📊",
    layout="wide"
)

# Title
st.title("📊 Scan Data Visualization")

# Get all scan directories
scan_dirs = [d for d in os.listdir("foundData") if d.startswith("scan_")]

# Sidebar for domain selection
selected_domain = st.sidebar.selectbox(
    "Select Domain",
    options=scan_dirs,
    format_func=lambda x: x.replace("scan_", "").replace("_20250608_", " - ")
)

if selected_domain:
    scan_path = os.path.join("foundData", selected_domain)
    
    # Create tabs for different data types
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "Web Technologies", "CVE Results", "SSL Certificates", 
        "Subdomains", "Domain Info"
    ])
    
    # Web Technologies Tab
    with tab1:
        st.header("Web Technologies")
        tech_file = os.path.join(scan_path, "web_technologies.json")
        if os.path.exists(tech_file):
            with open(tech_file, 'r') as f:
                tech_data = json.load(f)
                
            # Create a list for technologies
            tech_list = []
            for domain, data in tech_data.items():
                if data.get("status") == "success":
                    for tech in data.get("technologies", []):
                        tech_list.append({
                            "Domain": domain,
                            "Technology": tech["name"],
                            "Category": tech["categories"][0] if tech["categories"] else "Unknown",
                            "Confidence": tech["confidence"]
                        })
            
            if tech_list:
                # Display technologies in a table
                st.subheader("Detected Technologies")
                st.table(tech_list)
                
                # Display technology categories
                categories = {}
                for tech in tech_list:
                    cat = tech["Category"]
                    categories[cat] = categories.get(cat, 0) + 1
                
                st.subheader("Technology Categories")
                cols = st.columns(len(categories))
                for col, (category, count) in zip(cols, categories.items()):
                    col.metric(category, count)
            else:
                st.warning("No technology data available")
    
    # CVE Results Tab
    with tab2:
        st.header("CVE Scan Results")
        cve_file = os.path.join(scan_path, "cve_scan_results.json")
        if os.path.exists(cve_file):
            with open(cve_file, 'r') as f:
                cve_data = json.load(f)
            
            # Display CVE results
            st.json(cve_data)
    
    # SSL Certificates Tab
    with tab3:
        st.header("SSL Certificates")
        cert_file = os.path.join(scan_path, "certificates.json")
        if os.path.exists(cert_file):
            with open(cert_file, 'r') as f:
                cert_data = json.load(f)
            
            # Display certificate information
            st.json(cert_data)
    
    # Subdomains Tab
    with tab4:
        st.header("Subdomains")
        subdomains_file = os.path.join(scan_path, "all_subdomains.json")
        if os.path.exists(subdomains_file):
            with open(subdomains_file, 'r') as f:
                subdomains_data = json.load(f)
            
            # Display subdomains
            st.json(subdomains_data)
    
    # Domain Info Tab
    with tab5:
        st.header("Domain Information")
        lease_file = os.path.join(scan_path, "domainLease.json")
        if os.path.exists(lease_file):
            with open(lease_file, 'r') as f:
                lease_data = json.load(f)
            
            # Display domain lease information
            st.json(lease_data)

# Add footer
st.markdown("---")
st.markdown("EASM Scan Results Visualization Tool") 