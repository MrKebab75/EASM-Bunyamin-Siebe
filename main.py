# main.py
import subprocess

def main():
    scripts = {
        "1": "Scripts/Certificaat.py",
        "2": "Scripts/Domeingeldigheid.py",
        "3": "Scripts/subdom.py",
        "4": "Scripts/WhatRunsScan.py",
    }

    print("Select a script to run:")
    for key, script in scripts.items():
        print(f"{key}. {script}")

    choice = input("Enter the number of the script to run: ")

    if choice in scripts:
        subprocess.run(["python", scripts[choice]])
    else:
        print("Invalid choice.")

if __name__ == "__main__":
    main()
