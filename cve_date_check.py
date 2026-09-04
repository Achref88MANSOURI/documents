import json
import urllib.request
import urllib.parse
from datetime import datetime, timedelta

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

end_date = datetime.utcnow()
start_date = end_date - timedelta(days=118)  # margin for day-boundary padding below

params = {
    "cvssV3Severity": "CRITICAL",
    "resultsPerPage": 20,
    "startIndex": 0,
    "pubStartDate": start_date.strftime("%Y-%m-%dT00:00:00.000"),
    "pubEndDate": end_date.strftime("%Y-%m-%dT23:59:59.999"),
}
url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"
req = urllib.request.Request(url, headers={"Accept": "application/json"})
with urllib.request.urlopen(req, timeout=30) as resp:
    data = json.loads(resp.read())

print(f"Date range: {params['pubStartDate']} to {params['pubEndDate']}")
print(f"Total CRITICAL CVEs in this window: {data.get('totalResults', 0)}")
print()
for item in data.get("vulnerabilities", [])[:5]:
    cve = item["cve"]
    print(f"  {cve['id']}  published={cve.get('published', '')[:10]}")
