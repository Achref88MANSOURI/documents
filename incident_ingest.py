import json
import uuid
import urllib.request
from datetime import datetime

THEHIVE_URL = "http://172.20.24.228:9000"
THEHIVE_API_KEY = "XS5v1JbcWvC/qCX+3m3XFWEVpFt+yodq"
EMBED_URL = "http://localhost:8001/embed"
QDRANT_URL = "http://localhost:6333/collections/incident_history/points"
NAMESPACE = uuid.UUID('1a3f5c7e-9b2d-4e6a-8c1f-3d5b7e9a2c4f')

def fetch_closed_cases():
    query = {
        "query": [
            {"_name": "listCase"},
            {"_name": "filter", "_field": "stage", "_value": "Closed"},
            {"_name": "sort", "_fields": [{"_createdAt": "desc"}]},
            {"_name": "page", "from": 0, "to": 1000}
        ]
    }
    req = urllib.request.Request(
        f"{THEHIVE_URL}/api/v1/query",
        data=json.dumps(query).encode(),
        headers={
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {THEHIVE_API_KEY}'
        },
        method='POST',
    )
    with urllib.request.urlopen(req) as resp:
        return json.loads(resp.read())

def build_embedding_text(case):
    parts = [case.get('title', '')]
    desc = case.get('description', '')
    if desc:
        parts.append(desc[:500])
    summary = case.get('summary', '')
    if summary:
        parts.append(f"Summary: {summary}")
    tags = case.get('tags', [])
    if tags:
        rule_tags = [t for t in tags if t.startswith('rule:')]
        if rule_tags:
            parts.append(f"Rules: {', '.join(rule_tags)}")
    status = case.get('status', '')
    if status:
        parts.append(f"Resolution: {status}")
    return '\n'.join(parts)

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

def ts_to_date(ts_ms):
    if not ts_ms:
        return None
    return datetime.utcfromtimestamp(ts_ms / 1000).strftime('%Y-%m-%d')

def main():
    print("Fetching closed cases from TheHive...")
    cases = fetch_closed_cases()
    print(f"Found {len(cases)} closed cases")

    ok = 0
    for case in cases:
        case_id = case.get('_id', '')
        number = case.get('number', 0)
        title = case.get('title', '')
        severity = case.get('severity', 0)
        status = case.get('status', '')
        tags = case.get('tags', [])
        summary = case.get('summary', '')
        end_date = ts_to_date(case.get('endDate'))
        stage = case.get('stage', '')

        # derive attack_type from tags
        rule_tags = [t.replace('rule:', '') for t in tags if t.startswith('rule:')]
        engine_tags = [t.replace('engine:', '') for t in tags if t.startswith('engine:')]
        attack_type = rule_tags[0] if rule_tags else title

        embedding_text = build_embedding_text(case)
        point_id = str(uuid.uuid5(NAMESPACE, case_id))
        vector = get_embedding(embedding_text)

        payload = {
            'incident_id': case_id,
            'case_number': number,
            'title': title,
            'severity': severity,
            'status': status,
            'stage': stage,
            'attack_type': attack_type,
            'tags': tags,
            'summary': summary,
            'end_date': end_date,
            'engine': engine_tags[0] if engine_tags else 'unknown',
            'embedding_text': embedding_text,
        }

        upsert_point(point_id, vector, payload)
        ok += 1
        print(f"  Ingested case #{number}: {title[:60]} [{status}]")

    print(f"\nDone. {ok} cases ingested.")

if __name__ == '__main__':
    main()
