import json
import urllib.request
import urllib.parse
import urllib.error
from datetime import datetime, timedelta

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

end_date = datetime.utcnow()
start_date = end_date - timedelta(days=120)

params = {
    "cvssV3Severity": "CRITICAL",
    "resultsPerPage": 20,
    "startIndex": 0,
    "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
    "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
}
url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"
print("Full URL:")
print(url)
print()

req = urllib.request.Request(url, headers={"Accept": "application/json"})
try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read())
        print("Success:", data.get('totalResults', 0), "results")
except urllib.error.HTTPError as e:
    print(f"HTTP Error {e.code}: {e.reason}")
    print("Response body:")
    print(e.read().decode())
