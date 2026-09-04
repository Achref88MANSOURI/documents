import json
import urllib.request

EMBED_URL = 'http://localhost:8001/embed'
QDRANT_SEARCH_URL = 'http://localhost:6333/collections/cve_context/points/search'

QUERIES = [
    "remote code execution in Apache HTTP server allowing unauthenticated attacker",
    "privilege escalation vulnerability in Windows kernel",
    "SQL injection vulnerability in web application login page",
    "buffer overflow in OpenSSL cryptographic library",
]

def get_embedding(text):
    req = urllib.request.Request(
        EMBED_URL,
        data=json.dumps({'text': text}).encode(),
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())['embedding']

def search(vector, top_k=3):
    body = {
        'vector': vector,
        'limit': top_k,
        'with_payload': ['cve_id', 'severity', 'cvss_score', 'affected_products', 'published_date']
    }
    req = urllib.request.Request(
        QDRANT_SEARCH_URL,
        data=json.dumps(body).encode(),
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())

for q in QUERIES:
    vector = get_embedding(q)
    results = search(vector)
    print(f"Query: {q}")
    for r in results['result']:
        p = r['payload']
        products = ', '.join(p.get('affected_products', [])[:3]) or 'not specified'
        print(f"  {r['score']:.4f}  {p['cve_id']}  CVSS={p['cvss_score']}  {p['published_date']}  [{products}]")
    print()
