from flask import Flask, render_template, request, redirect, url_for
import subprocess

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
    return render_template("index.html", scripts=scripts, output=output)

if __name__ == "__main__":
    app.run(debug=True)
