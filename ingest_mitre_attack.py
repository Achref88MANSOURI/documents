#!/usr/bin/env python3
"""
Ingests CVE intelligence into the `triage_kb` Qdrant collection, under
collection="cve_intel". This is what the agent's rag_tool queries to answer:
  - "Is the CVE involved actively weaponized (KEV)?"
  - "What does this IOC/CVE reputation actually imply?"

Data sources:
  1. CISA Known Exploited Vulnerabilities (KEV) catalog — REQUIRED, primary source.
     This is the actionable "is it actively exploited" signal, curated by CISA,
     ~1400 entries. Full catalog fits comfortably in a vector DB; unlike raw NVD
     (250k+ CVEs) there's no reason to filter it down further.
     Primary: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
     Mirror:  https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json
     (falls back to the GitHub mirror automatically if cisa.gov is unreachable —
     common on networks that only allowlist github.com)

  2. NVD CVE API 2.0 — OPTIONAL enrichment (--with-cvss), adds a CVSS base score
     and severity per CVE. Off by default because it's slow: NVD rate-limits
     unauthenticated requests to 5 req/30s, so ~1400 CVEs takes ~30+ minutes.
     Get a free key at https://nvd.nist.gov/developers/request-an-api-key and
     pass --api-key to raise the limit to 50 req/30s (~2-3 min instead).

Logic recap (mirrors ingest_mitre_attack.py conventions):
  - One chunk per CVE (natural unit)
  - Point ID = UUID5 derived from "cve_intel:<cve_id>" (deterministic, so
    re-running this script updates existing entries instead of duplicating them)
  - Same Qdrant collection (triage_kb) as MITRE ATT&CK data, distinguished by
    the payload["collection"] = "cve_intel" field, per the rag_tool schema

Usage:
  python3 ingest_cve_intel.py --dry-run                 # parse + preview only
  python3 ingest_cve_intel.py --limit 10                 # quick test batch
  python3 ingest_cve_intel.py                             # full run, no CVSS
  python3 ingest_cve_intel.py --with-cvss --api-key KEY   # full run + CVSS enrichment
"""

import argparse
import json
import re
import sys
import time
import urllib.request
import urllib.error
import uuid

EMBED_URL = "http://localhost:8001/embed"
QDRANT_URL = "http://localhost:6333/collections/triage_kb/points"
KEV_URL_PRIMARY = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_URL_MIRROR = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
BATCH_SIZE = 50  # points per upsert call to Qdrant
NVD_DELAY_NO_KEY = 6.5   # seconds between calls, keeps us under 5 req/30s
NVD_DELAY_WITH_KEY = 0.7  # seconds between calls, keeps us under 50 req/30s

WS_RE = re.compile(r"\s+")


def clean(text):
    return WS_RE.sub(" ", (text or "")).strip()


def load_kev_catalog(path_or_none, prefer_mirror):
    if path_or_none:
        with open(path_or_none) as f:
            return json.load(f)

    urls = [KEV_URL_MIRROR, KEV_URL_PRIMARY] if prefer_mirror else [KEV_URL_PRIMARY, KEV_URL_MIRROR]
    last_err = None
    for url in urls:
        try:
            print(f"Downloading CISA KEV catalog from {url} ...", file=sys.stderr)
            with urllib.request.urlopen(url, timeout=30) as resp:
                return json.load(resp)
        except Exception as e:
            print(f"  failed ({e}), trying next source", file=sys.stderr)
            last_err = e
    raise RuntimeError(f"Could not download KEV catalog from any source: {last_err}")


def extract_cves(catalog):
    """Pull usable vulnerability entries from the KEV catalog JSON."""
    entries = []
    for v in catalog.get("vulnerabilities", []):
        cve_id = v.get("cveID")
        if not cve_id:
            continue  # no CVE ID means we can't form a stable point ID - skip
        entries.append({
            "cve_id": cve_id,
            "vendor_project": v.get("vendorProject", ""),
            "product": v.get("product", ""),
            "vulnerability_name": v.get("vulnerabilityName", ""),
            "date_added": v.get("dateAdded", ""),
            "short_description": clean(v.get("shortDescription", "")),
            "required_action": clean(v.get("requiredAction", "")),
            "due_date": v.get("dueDate", ""),
            "known_ransomware_use": v.get("knownRansomwareCampaignUse", "Unknown"),
            "cwes": v.get("cwes", []) or [],
        })
    return entries


def fetch_cvss(cve_id, api_key):
    """Best-effort NVD lookup. Returns (score, severity) or (None, None)."""
    req = urllib.request.Request(f"{NVD_API_URL}?cveId={cve_id}")
    if api_key:
        req.add_header("apiKey", api_key)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        print(f"  NVD lookup failed for {cve_id}: {e}", file=sys.stderr)
        return None, None

    vulns = data.get("vulnerabilities", [])
    if not vulns:
        return None, None
    metrics = vulns[0].get("cve", {}).get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            m = metrics[key][0]
            cvss_data = m.get("cvssData", {})
            score = cvss_data.get("baseScore")
            severity = m.get("baseSeverity") or cvss_data.get("baseSeverity")
            if score is not None:
                return score, severity
    return None, None


def build_chunk_text(t):
    parts = [
        f"{t['cve_id']} - {t['vulnerability_name']} "
        f"({t['vendor_project']} {t['product']}): {t['short_description']}",
        f"This CVE is in the CISA Known Exploited Vulnerabilities (KEV) catalog "
        f"(added {t['date_added']}), meaning it has been observed as actively "
        f"exploited in the wild.",
        f"Known ransomware campaign use: {t['known_ransomware_use']}.",
    ]
    if t["required_action"]:
        parts.append(f"Required action: {t['required_action']} (due {t['due_date']}).")
    if t.get("cvss_score") is not None:
        parts.append(f"CVSS base score: {t['cvss_score']} ({t['cvss_severity']}).")
    if t["cwes"]:
        parts.append(f"Weakness types: {', '.join(t['cwes'])}.")
    return " ".join(parts)


def deterministic_id(cve_id):
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"cve_intel:{cve_id}"))


def embed(text):
    req = urllib.request.Request(
        EMBED_URL,
        data=json.dumps({"text": text}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())["embedding"]


def upsert_batch(points):
    req = urllib.request.Request(
        QDRANT_URL,
        data=json.dumps({"points": points}).encode(),
        headers={"Content-Type": "application/json"},
        method="PUT",
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--kev-file", default=None,
                         help="local KEV JSON path (default: download, cisa.gov then GitHub mirror)")
    parser.add_argument("--prefer-mirror", action="store_true",
                         help="try the GitHub mirror before cisa.gov (useful if cisa.gov is blocked)")
    parser.add_argument("--dry-run", action="store_true",
                         help="parse and preview entries only, no embedding/Qdrant/NVD calls")
    parser.add_argument("--limit", type=int, default=None,
                         help="only process the first N CVEs (useful for a quick test batch)")
    parser.add_argument("--with-cvss", action="store_true",
                         help="enrich each CVE with a CVSS score/severity from the NVD API (slow, rate-limited)")
    parser.add_argument("--api-key", default=None,
                         help="NVD API key, raises the rate limit from 5 to 50 req/30s")
    args = parser.parse_args()

    catalog = load_kev_catalog(args.kev_file, args.prefer_mirror)
    entries = extract_cves(catalog)
    if args.limit:
        entries = entries[:args.limit]

    print(f"Found {len(entries)} KEV entries.", file=sys.stderr)

    if args.dry_run:
        for t in entries[:5]:
            print("---")
            print(build_chunk_text(t)[:300])
        print(f"\n(dry run - showed 5 of {len(entries)}, no network calls made beyond the KEV download)")
        return

    delay = NVD_DELAY_WITH_KEY if args.api_key else NVD_DELAY_NO_KEY

    batch = []
    done = 0
    for t in entries:
        if args.with_cvss:
            score, severity = fetch_cvss(t["cve_id"], args.api_key)
            t["cvss_score"] = score
            t["cvss_severity"] = severity
            time.sleep(delay)
        else:
            t["cvss_score"] = None
            t["cvss_severity"] = None

        text = build_chunk_text(t)
        try:
            vector = embed(text)
        except Exception as e:
            print(f"SKIP {t['cve_id']}: embed failed ({e})", file=sys.stderr)
            continue

        batch.append({
            "id": deterministic_id(t["cve_id"]),
            "vector": vector,
            "payload": {
                "text": text,
                "collection": "cve_intel",
                "source": t["cve_id"],
                "metadata": {
                    "cve_id": t["cve_id"],
                    "vendor_project": t["vendor_project"],
                    "product": t["product"],
                    "vulnerability_name": t["vulnerability_name"],
                    "date_added": t["date_added"],
                    "known_ransomware_use": t["known_ransomware_use"],
                    "kev": True,
                    "cwes": t["cwes"],
                    "cvss_score": t["cvss_score"],
                    "cvss_severity": t["cvss_severity"],
                },
            },
        })

        if len(batch) >= BATCH_SIZE:
            upsert_batch(batch)
            done += len(batch)
            print(f"upserted {done}/{len(entries)}", file=sys.stderr)
            batch = []

    if batch:
        upsert_batch(batch)
        done += len(batch)
        print(f"upserted {done}/{len(entries)}", file=sys.stderr)

    print(f"Done. {done} CVEs ingested into triage_kb (collection=cve_intel).")


if __name__ == "__main__":
    main()
