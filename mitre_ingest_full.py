import json
import re
import time
import uuid
import urllib.request

BUNDLE_PATH = '/home/ai-vm/enterprise-attack.json'
EMBED_URL = 'http://localhost:8001/embed'
QDRANT_URL = 'http://localhost:6333/collections/mitre_techniques/points'
NAMESPACE = uuid.UUID('7c9f5e2a-1b3d-4c6e-9a8f-2d5b7e1c4a6f')

def strip_citations(text):
    text = re.sub(r'\(Citation:[^)]*\)', '', text)
    text = re.sub(r'\[([^\]]*)\]\([^)]*\)', r'\1', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text

def join_clean(parts):
    out = []
    for p in parts:
        if not p:
            continue
        p = p.strip()
        if p and p[-1] in '.!?':
            p = p[:-1]
        out.append(p)
    return '. '.join(out) + '.'

def first_sentences(text, n=3):
    sentences = re.split(r'(?<=[.!?])\s+', text)
    return ' '.join(sentences[:n]).rstrip()

def get_technique_id(obj):
    for ref in obj.get('external_references', []):
        if ref.get('source_name') == 'mitre-attack':
            return ref.get('external_id')
    return None

def get_tactics(obj):
    return [kc['phase_name'] for kc in obj.get('kill_chain_phases', [])
            if kc.get('kill_chain_name') == 'mitre-attack']

def process_technique(technique, objects_by_id, detects_map):
    technique_id = get_technique_id(technique)
    if not technique_id:
        return None
    name = technique['name']
    tactics = get_tactics(technique)
    platforms = technique.get('x_mitre_platforms', [])
    is_sub = technique.get('x_mitre_is_subtechnique', False)
    parent_id = technique_id.split('.')[0] if is_sub else None
    version = technique.get('x_mitre_version')
    description = strip_citations(technique.get('description', ''))
    description_short = first_sentences(description, 3)

    strategy_id = detects_map.get(technique['id'])
    analytic_descriptions = []
    log_sources = []
    detection_strategy_ext_id = None
    analytic_ids = []

    if strategy_id:
        strategy = objects_by_id.get(strategy_id)
        if strategy:
            for ref in strategy.get('external_references', []):
                if ref.get('source_name') == 'mitre-attack':
                    detection_strategy_ext_id = ref.get('external_id')
            for analytic_ref in strategy.get('x_mitre_analytic_refs', []):
                analytic = objects_by_id.get(analytic_ref)
                if analytic:
                    for ref in analytic.get('external_references', []):
                        if ref.get('source_name') == 'mitre-attack':
                            analytic_ids.append(ref.get('external_id'))
                    analytic_descriptions.append(strip_citations(analytic.get('description', '')))
                    for log_ref in analytic.get('x_mitre_log_source_references', []):
                        log_sources.append(log_ref.get('name'))

    embedding_text_parts = [', '.join(tactics), f"{name} ({technique_id})", description_short]
    embedding_text = join_clean(embedding_text_parts)
    if analytic_descriptions:
        embedding_text += ' Detection: ' + join_clean(analytic_descriptions)
    if log_sources:
        embedding_text += ' Log sources: ' + ', '.join(sorted(set(log_sources))) + '.'

    payload = {
        'technique_id': technique_id,
        'name': name,
        'tactic': tactics,
        'platforms': platforms,
        'is_sub_technique': is_sub,
        'parent_technique_id': parent_id,
        'x_mitre_version': version,
        'detection_strategy_id': detection_strategy_ext_id,
        'analytic_ids': analytic_ids,
        'log_sources': sorted(set(log_sources)),
        'embedding_text': embedding_text,
    }
    return technique_id, embedding_text, payload

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
    with open(BUNDLE_PATH) as f:
        data = json.load(f)
    objects_by_id = {obj['id']: obj for obj in data['objects']}
    detects_map = {}
    for obj in data['objects']:
        if obj.get('type') == 'relationship' and obj.get('relationship_type') == 'detects':
            detects_map[obj['target_ref']] = obj['source_ref']

    live_techniques = [
        obj for obj in data['objects']
        if obj.get('type') == 'attack-pattern'
        and not obj.get('revoked')
        and not obj.get('x_mitre_deprecated')
    ]

    print(f"Found {len(live_techniques)} live techniques to ingest")

    ok, failed, no_strategy = 0, 0, 0
    start = time.time()

    for i, technique in enumerate(live_techniques, 1):
        try:
            result = process_technique(technique, objects_by_id, detects_map)
            if result is None:
                failed += 1
                continue
            technique_id, embedding_text, payload = result
            if not payload['detection_strategy_id']:
                no_strategy += 1
            point_id = str(uuid.uuid5(NAMESPACE, technique_id))
            vector = get_embedding(embedding_text)
            upsert_point(point_id, vector, payload)
            ok += 1
        except Exception as e:
            failed += 1
            print(f"  FAILED on {technique.get('id')}: {e}")

        if i % 50 == 0 or i == len(live_techniques):
            elapsed = time.time() - start
            print(f"  {i}/{len(live_techniques)} processed ({ok} ok, {failed} failed) — {elapsed:.1f}s elapsed")

    print(f"\nDone. {ok} ingested, {failed} failed, {no_strategy} had no detection strategy.")

if __name__ == '__main__':
    main()
