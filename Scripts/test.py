import ast
import datetime
import json
import sys
import requests
import urllib.parse
from tabulate import tabulate

url = "https://www.whatruns.com/api/v1/get_site_apps"
data = {
    "data": {
        "hostname": sys.argv[1],
        "url": sys.argv[1],
        "rawhostname": sys.argv[1]
    }
}
data = urllib.parse.urlencode({k: json.dumps(v) for k, v in data.items()})
data = data.replace('+', '')
headers = {'Content-Type': 'application/x-www-form-urlencoded'}
response = requests.post(url, data=data, headers=headers)
loaded = json.loads(response.content)
apps = ast.literal_eval(loaded['apps'])
print(apps)
nuance = list(apps.keys())[0]  # In Python 3, pop() on dict_keys is not allowed

entries = []
for app_type, values in apps[nuance].items():
    for item in values:
        dt = datetime.datetime.fromtimestamp(item['detectedTime'] / 1000)
        ldt = datetime.datetime.fromtimestamp(item['latestDetectedTime'] / 1000)
        entries.append({
            'Type': app_type,
            'Name': item['name'],
            'Detected': dt,
            'Last_Detected': ldt,
            'Version': item.get('version', 'Unknown')
        })

print(tabulate(entries, headers='keys'))

# import ast
# import json
# import sys
# import requests
# import urllib
# import subprocess
# import os

# # Functie om te controleren of een pakket is ge誰nstalleerd
# def check_and_install(package):
#     try:
#         subprocess.run(["dpkg", "-l", package], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
#     except subprocess.CalledProcessError:
#         print(f"{package} is niet ge誰nstalleerd. Het wordt nu ge誰nstalleerd...")
#         subprocess.run(["sudo", "apt-get", "install", "-y", package], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
#         print(f"{package} is succesvol ge誰nstalleerd.")

# # Vereiste pakketten
# required_tools = ["python3-requests", "python3-urllib3", "python3-tabulate"]
# for tool in required_tools:
#     check_and_install(tool)

# # Functie om resultaten in een JSON-bestand op te slaan
# def save_results_to_json(data, filename):
#     with open(filename, 'w', encoding='utf-8') as f:
#         json.dump(data, f, indent=4, ensure_ascii=False)
#     print(f"Resultaten zijn opgeslagen in: {filename}")

# def main():
#     script_dir = os.path.dirname(os.path.abspath(__file__))
#     project_root = os.path.abspath(os.path.join(script_dir, '..'))
#     output_dir = os.path.join(project_root, "scan_results")

#     if not os.path.exists(output_dir):
#         os.makedirs(output_dir)
#         print(f"De directory 'scan_results' is aangemaakt op {output_dir}")

#     domain = input("Voer de domeinnaam in waarop je de softwaretoepassingen wilt analyseren: ").strip()
#     if not domain:
#         print("Geen domeinnaam opgegeven. Het programma wordt afgesloten.")
#         sys.exit(1)

#     url = "https://www.whatruns.com/api/v1/get_site_apps"
#     data = {"data": {"hostname": domain, "url": domain, "rawhostname": domain}}
#     data = urllib.parse.urlencode({k: json.dumps(v) for k, v in data.items()}).replace('+', '')
#     headers = {'Content-Type': 'application/x-www-form-urlencoded'}

#     response = requests.post(url, data=data, headers=headers)
#     if response.status_code != 200:
#         print(f"Fout bij het ophalen van gegevens: {response.status_code}")
#         sys.exit(1)

#     loaded = json.loads(response.content)
#     apps_str = loaded.get('apps')
#     if not apps_str:
#         print("Fout: 'apps' niet gevonden in de API-respons.")
#         sys.exit(1)

#     try:
#         apps = json.loads(apps_str)
#     except Exception as e:
#         print("Kon 'apps' niet decoderen:", e)
#         print("Inhoud van 'apps':", apps_str)
#         sys.exit(1)

#     if isinstance(apps, dict):
#         nuance = list(apps.keys())[0]
#     else:
#         print("'apps' is geen geldige dictionary:", apps)
#         sys.exit(1)

#     technology_versions = []
#     for app_type, values in apps[nuance].items():
#         for item in values:
#             version = item.get('version', 'N/A')
#             technology_versions.append({
#                 "name": item['name'],
#                 "version": version,
#                 "type": app_type
#             })

#     filename = os.path.join(output_dir, f"{domain}_technology_versions.json")
#     save_results_to_json(technology_versions, filename)

# if __name__ == "__main__":
#     main()