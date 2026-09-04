import json
import time
import uuid
import urllib.request
import urllib.parse
from datetime import datetime, timedelta

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EMBED_URL = "http://localhost:8001/embed"
QDRANT_URL = "http://localhost:6333/collections/cve_context/points"
QDRANT_SCROLL = "http://localhost:6333/collections/cve_context/points/scroll"
NAMESPACE = uuid.UUID('2b8e4f6a-9c1d-4a3e-8f5b-6d2c9e4a7b1f')
NVD_REQUEST_DELAY = 6
WINDOW_DAYS = 118
TOTAL_DAYS_BACK = 730

def get_existing_ids():
    existing = set()
    offset = None
    while True:
        body = {"limit": 250, "with_payload": ["cve_id"], "with_vector": False}
        if offset:
            body["offset"] = offset
        req = urllib.request.Request(
            QDRANT_SCROLL,
            data=json.dumps(body).encode(),
            headers={'Content-Type': 'application/json'},
            method='POST',
        )
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read())
        for pt in data["result"]["points"]:
            cve_id = pt.get("payload", {}).get("cve_id")
            if cve_id:
                existing.add(cve_id)
        offset = data["result"].get("next_page_offset")
        if not offset:
            break
    return existing

def nvd_fetch(start_str, end_str, start_index=0, results_per_page=100):
    params = {
        "cvssV3Severity": "CRITICAL",
        "resultsPerPage": results_per_page,
        "startIndex": start_index,
        "pubStartDate": start_str,
        "pubEndDate": end_str,
    }
    url = f"{NVD_API_URL}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())

def parse_nvd_response(data):
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
        cvss_score, cvss_vector, actual_severity = 0.0, "", "CRITICAL"
        for v in ["cvssMetricV31", "cvssMetricV30"]:
            if v in metrics and metrics[v]:
                d = metrics[v][0].get("cvssData", {})
                cvss_score = d.get("baseScore", 0.0)
                cvss_vector = d.get("vectorString", "")
                actual_severity = metrics[v][0].get("baseSeverity", "CRITICAL")
                break
        affected_products = []
        for config in cve.get("configurations", []):
            for node in config.get("nodes", []):
                for cpe in node.get("cpeMatch", []):
                    parts = cpe.get("criteria", "").split(":")
                    if len(parts) >= 5 and parts[3] != "*" and parts[4] != "*":
                        affected_products.append(f"{parts[3]}:{parts[4]}")
        affected_products = list(set(affected_products))[:10]
        published_date = cve.get("published", "")[:10]
        ref_urls = [r.get("url", "") for r in cve.get("references", [])[:5]]
        doc = f"""CVE ID: {cve_id}
Severity: {actual_severity}
CVSS Score: {cvss_score}
CVSS Vector: {cvss_vector}
Published: {published_date}

Description: {description}

Affected Products: {', '.join(affected_products) if affected_products else 'Not specified'}

References: {', '.join(ref_urls) if ref_urls else 'None'}"""
        documents.append({"id": cve_id, "document": doc, "metadata": {
            "cve_id": cve_id,
            "cvss_score": float(cvss_score),
            "severity": actual_severity,
            "published_date": published_date,
            "affected_products": affected_products,
            "type": "cve",
        }})
    return documents

def get_embedding(text):
    req = urllib.request.Request(
        EMBED_URL, data=json.dumps({'text': text}).encode(),
        headers={'Content-Type': 'application/json'}, method='POST',
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())['embedding']

def upsert_point(point_id, vector, payload):
    body = {'points': [{'id': point_id, 'vector': vector, 'payload': payload}]}
    req = urllib.request.Request(
        QDRANT_URL, data=json.dumps(body).encode(),
        headers={'Content-Type': 'application/json'}, method='PUT',
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())

def main():
    print("Loading existing CVE IDs from Qdrant...")
    existing = get_existing_ids()
    print(f"Already ingested: {len(existing)} CVEs")

    now = datetime.utcnow()
    earliest = now - timedelta(days=TOTAL_DAYS_BACK)
    windows, window_end = [], now
    while window_end > earliest:
        window_start = max(window_end - timedelta(days=WINDOW_DAYS), earliest)
        windows.append((window_start, window_end))
        window_end = window_start

    all_cves, seen_ids, first = [], set(), True
    for i, (w_start, w_end) in enumerate(windows, 1):
        start_str = w_start.strftime("%Y-%m-%dT00:00:00.000")
        end_str = w_end.strftime("%Y-%m-%dT23:59:59.999")
        if not first:
            time.sleep(NVD_REQUEST_DELAY)
        first = False
        page_data = nvd_fetch(start_str, end_str, start_index=0)
        total = page_data.get("totalResults", 0)
        print(f"Window {i}/{len(windows)}: {start_str[:10]} to {end_str[:10]} — {total} CVEs")
        window_cves = parse_nvd_response(page_data)
        for page in range(1, (total + 99) // 100):
            time.sleep(NVD_REQUEST_DELAY)
            window_cves.extend(parse_nvd_response(
                nvd_fetch(start_str, end_str, start_index=page * 100)))
        for c in window_cves:
            if c['id'] not in seen_ids:
                seen_ids.add(c['id'])
                all_cves.append(c)

    to_ingest = [c for c in all_cves if c['id'] not in existing]
    print(f"\nTotal collected: {len(all_cves)} | Already ingested: {len(existing)} | To ingest: {len(to_ingest)}")

    ok = 0
    for i, c in enumerate(to_ingest, 1):
        point_id = str(uuid.uuid5(NAMESPACE, c['id']))
        vector = get_embedding(c['document'])
        upsert_point(point_id, vector, c['metadata'])
        ok += 1
        if i % 100 == 0 or i == len(to_ingest):
            print(f"  {i}/{len(to_ingest)} ingested")

    print(f"\nDone. {ok} new CVEs ingested. Total in collection: {len(existing) + ok}")

if __name__ == '__main__':
    main()
