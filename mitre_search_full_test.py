import json
import urllib.request

EMBED_URL = 'http://localhost:8001/embed'
QDRANT_SEARCH_URL = 'http://localhost:6333/collections/mitre_techniques/points/search'

# Each tuple: (evidence_text, expected_technique_id)
# These are realistic Agent-1-style evidence summaries with known answers
QUERIES = [
    (
        "process injected code into another process via shared memory section, redirected function pointer using SetWindowLong, triggered execution via SendNotifyMessage",
        "T1055.011"
    ),
    (
        "schtasks.exe created a new scheduled task running from SYSTEM context, task executes powershell.exe at logon",
        "T1053.005"
    ),
    (
        "mimikatz.exe executed, lsass.exe memory read, credential dumping detected via API call to MiniDumpWriteDump",
        "T1003.001"
    ),
    (
        "powershell encoded command executed, base64 decoded payload downloaded from external IP, outbound HTTP connection established",
        "T1059.001"
    ),
    (
        "registry run key modified under HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run to persist executable",
        "T1547.001"
    ),
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

hits_at_1 = 0
hits_at_5 = 0

for evidence_text, expected_id in QUERIES:
    vector = get_embedding(evidence_text)
    results = search(vector, top_k=5)
    returned_ids = [r['payload']['technique_id'] for r in results['result']]
    top1 = returned_ids[0] if returned_ids else None
    in_top5 = expected_id in returned_ids

    if top1 == expected_id:
        hits_at_1 += 1
    if in_top5:
        hits_at_5 += 1

    status = "HIT@1" if top1 == expected_id else ("HIT@5" if in_top5 else "MISS")
    print(f"[{status}] Expected: {expected_id}")
    for i, r in enumerate(results['result'], 1):
        marker = " <-- EXPECTED" if r['payload']['technique_id'] == expected_id else ""
        print(f"  {i}. {r['score']:.4f}  {r['payload']['technique_id']}  {r['payload']['name']}{marker}")
    print()

print(f"Recall@1: {hits_at_1}/{len(QUERIES)}")
print(f"Recall@5: {hits_at_5}/{len(QUERIES)}")
