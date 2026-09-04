import json
import urllib.request

EMBED_URL = 'http://localhost:8001/embed'
QDRANT_SEARCH_URL = 'http://localhost:6333/collections/incident_history/points/search'

QUERIES = [
    "powershell invoke-webrequest downloading executable from github",
    "suspicious powershell execution downloading binary to temp directory",
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

def search(vector, top_k=2):
    body = {
        'vector': vector,
        'limit': top_k,
        'with_payload': ['case_number', 'title', 'status', 'severity', 'attack_type', 'summary']
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
        print(f"  {r['score']:.4f}  Case#{p['case_number']}  [{p['status']}]  {p['attack_type'][:50]}")
        if p.get('summary'):
            print(f"           Summary: {p['summary']}")
    print()
