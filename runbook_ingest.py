import json
import re
import uuid
import urllib.request
from pathlib import Path

RUNBOOKS_DIR = Path.home() / "runbooks"
EMBED_URL = "http://localhost:8001/embed"
QDRANT_URL = "http://localhost:6333/collections/soc_playbooks/points"
NAMESPACE = uuid.UUID('9f3e7c1a-4b2d-4e6f-8a1c-3d5e7f9b1c3d')

CATEGORIES = {
    "brute-force": "Credential Attack",
    "brute_force": "Credential Attack",
    "ssh": "Credential Attack",
    "malware": "Malware",
    "phishing": "Social Engineering",
    "privilege": "Privilege Escalation",
    "exfiltration": "Data Loss",
    "ransomware": "Ransomware",
    "unauthorized": "Unauthorized Access",
    "access": "Unauthorized Access",
}

def categorize_runbook(title, runbook_id):
    text = (title + " " + runbook_id).lower()
    for keyword, category in CATEGORIES.items():
        if keyword in text:
            return category
    return "General Security"

def parse_runbook(md_file):
    content = md_file.read_text(encoding='utf-8')
    sections = []

    title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
    title = title_match.group(1).strip() if title_match else md_file.stem.replace('-', ' ').title()

    runbook_id = md_file.stem.lower().replace(' ', '-').replace('_', '-')
    category = categorize_runbook(title, runbook_id)

    section_pattern = re.compile(r'^##\s+(.+)$', re.MULTILINE)
    section_matches = list(section_pattern.finditer(content))

    if not section_matches:
        sections.append({
            "id": f"{runbook_id}-full",
            "document": f"Runbook: {title}\n\n{content}",
            "metadata": {
                "runbook_id": runbook_id,
                "title": title,
                "category": category,
                "section": "full",
                "type": "runbook",
            }
        })
        return sections

    for idx, match in enumerate(section_matches):
        section_title = match.group(1).strip()
        section_start = match.end()
        section_end = section_matches[idx + 1].start() if idx + 1 < len(section_matches) else len(content)
        section_body = content[section_start:section_end].strip()

        if not section_body:
            continue

        doc = f"""Runbook: {title}
Category: {category}
Section: {section_title}

{section_body}"""

        section_id = f"{runbook_id}-{section_title.lower().replace(' ', '-')}"
        section_id = re.sub(r'[^a-z0-9-]', '', section_id)[:100]

        sections.append({
            "id": section_id,
            "document": doc,
            "metadata": {
                "runbook_id": runbook_id,
                "title": title,
                "category": category,
                "section": section_title,
                "type": "runbook",
            }
        })

    return sections

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
    md_files = sorted(RUNBOOKS_DIR.glob("*.md"))
    print(f"Found {len(md_files)} runbook files")

    total_sections = 0
    for md_file in md_files:
        sections = parse_runbook(md_file)
        print(f"  {md_file.name}: {len(sections)} sections")
        for s in sections:
            point_id = str(uuid.uuid5(NAMESPACE, s['id']))
            vector = get_embedding(s['document'])
            payload = dict(s['metadata'])
            payload['runbook_section_id'] = s['id']
            payload['document_text'] = s['document']
            upsert_point(point_id, vector, payload)
            total_sections += 1

    print(f"\nDone. {total_sections} sections ingested.")

if __name__ == '__main__':
    main()
