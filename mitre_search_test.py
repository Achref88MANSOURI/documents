import json
import urllib.request

EMBED_URL = 'http://localhost:8001/embed'
QDRANT_SEARCH_URL = 'http://localhost:6333/collections/mitre_techniques/points/search'

QUERY_TEXT = "process wrote to shared memory section then redirected a function pointer to trigger code execution via a window message"

def get_embedding(text):
    req = urllib.request.Request(
        EMBED_URL,
        data=json.dumps({'text': text}).encode(),
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())['embedding']

def search(vector, top_k=5):
    body = {'vector': vector, 'limit': top_k, 'with_payload': ['technique_id', 'name']}
    req = urllib.request.Request(
        QDRANT_SEARCH_URL,
        data=json.dumps(body).encode(),
        headers={'Content-Type': 'application/json'},
        method='POST',
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())

vector = get_embedding(QUERY_TEXT)
results = search(vector)
for r in results['result']:
    print(f"{r['score']:.4f}  {r['payload']['technique_id']}  {r['payload']['name']}")
