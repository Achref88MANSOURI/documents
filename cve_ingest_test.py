import json
import time
import uuid
import urllib.request
import urllib.parse

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EMBED_URL = "http://localhost:8001/embed"
QDRANT_URL = "http://localhost:6333/collections/cve_context/points"
NAMESPACE = uuid.UUID('2b8e4f6a-9c1d-4a3e-8f5b-6d2c9e4a7b1f')

def fetch_nvd_page(severity, start_index=0, results_per_page=100):
    params = {
        "cvssV3Severity": severity,
        "resultsPerPage": results_per_page,
        "startIndex": start_index,
    }
    url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())

def parse_nvd_response(data, severity):
    documents = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN")

        descriptions = cve.get("descriptions", [])
        description = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            descriptions[0]["value"] if descriptions else "No description available"
        )

        metrics = cve.get("metrics", {})
        cvss_score, cvss_vector, actual_severity = 0.0, "", severity
        for cvss_version in ["cvssMetricV31", "cvssMetricV30"]:
            if cvss_version in metrics and metrics[cvss_version]:
                cvss_data = metrics[cvss_version][0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore", 0.0)
                cvss_vector = cvss_data.get("vectorString", "")
                actual_severity = metrics[cvss_version][0].get("baseSeverity", severity)
                break

        affected_products = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    parts = cpe_match.get("criteria", "").split(":")
                    if len(parts) >= 5:
                        vendor, product = parts[3], parts[4]
                        if vendor != "*" and product != "*":
                            affected_products.append(f"{vendor}:{product}")
        affected_products = list(set(affected_products))[:10]

        references = cve.get("references", [])
        ref_urls = [r.get("url", "") for r in references[:5]]

        published_date = cve.get("published", "")
        if published_date:
            published_date = published_date[:10]

        doc = f"""CVE ID: {cve_id}
Severity: {actual_severity}
CVSS Score: {cvss_score}
CVSS Vector: {cvss_vector}
Published: {published_date}

Description: {description}

Affected Products: {', '.join(affected_products) if affected_products else 'Not specified'}

References: {', '.join(ref_urls) if ref_urls else 'None'}"""

        metadata = {
            "cve_id": cve_id,
            "cvss_score": float(cvss_score),
            "severity": actual_severity,
            "published_date": published_date,
            "affected_products": affected_products,  # native array, not JSON string
            "type": "cve",
        }

        documents.append({"id": cve_id, "document": doc, "metadata": metadata})
    return documents

def get_embedding(text):
    req = urllib.request.Request(
        EMBED_URL,
        data=json.dumps({'text': text}).encode(),
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())['embedding']

def upsert_point(point_id, vector, payload):
    body = {'points': [{'id': point_id, 'vector': vector, 'payload': payload}]}
    req = urllib.request.Request(
        QDRANT_URL,
        data=json.dumps(body).encode(),
        headers={'Content-Type': 'application/json'},
        method='PUT',
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())

def main():
    print("Fetching 1 page (100 CRITICAL CVEs) from NVD API v2...")
    data = fetch_nvd_page("CRITICAL", start_index=0, results_per_page=100)
    print(f"Total CRITICAL CVEs available: {data.get('totalResults', 0)}")

    cves = parse_nvd_response(data, "CRITICAL")
    print(f"Parsed {len(cves)} CVEs from this page")

    ok = 0
    for c in cves:
        point_id = str(uuid.uuid5(NAMESPACE, c['id']))
        vector = get_embedding(c['document'])
        upsert_point(point_id, vector, c['metadata'])
        ok += 1

    print(f"\nDone. {ok} CVEs ingested (test page only).")

if __name__ == '__main__':
    main()
