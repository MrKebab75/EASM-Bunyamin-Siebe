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
            'Last_Detected': ldt
        })

print(tabulate(entries, headers='keys'))