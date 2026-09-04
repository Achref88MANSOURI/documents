import json
import urllib.request

EMBED_URL = 'http://localhost:8001/embed'
QDRANT_SEARCH_URL = 'http://localhost:6333/collections/soc_playbooks/points/search'

QUERIES = [
    "user reported suspicious email with malicious link, need to check headers and identify other recipients",
    "multiple failed SSH login attempts from external IP against root account",
    "large volume of data uploaded to external cloud storage from finance workstation",
    "ransomware note found on file server, files encrypted with unknown extension",
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
    body = {'vector': vector, 'limit': top_k, 'with_payload': ['runbook_id', 'title', 'section', 'category']}
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
        print(f"  {r['score']:.4f}  [{p['runbook_id']}] {p['title']} — {p['section']} ({p['category']})")
    print()
