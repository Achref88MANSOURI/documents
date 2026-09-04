"""
Build a COMPLETE TheHive 5 "create alert" request body -- metadata AND
observables -- from a raw SOC alert of ANY shape (Sigma / YARA / Suricata
via Security Onion -> n8n). One node, one POST.

This merges what used to be two separate Code nodes:
  - IOC extraction (walks the whole alert tree, validates every candidate
    with ipaddress/urlparse, filters infrastructure noise)
  - Alert metadata resolution (engine/severity/rule/time/sourceRef)

Observables come in two flavors, both present in the output: `ioc: true`
threat-intel observables (external IPs, domains, URLs, file hashes -- fit
to check against a reputation feed), and `ioc: false` response observables
(hostname, host/agent id, process/parent identity, user identity, registry,
file path -- the handles a responder needs to actually DO something:
isolate a host, kill a process, disable an account). Every observable
carries an `re&ct:<category>` tag (network/file/process/configuration/
identity) so downstream automation can filter by which kind it's looking at.

Field coverage is grounded in `so-alert-reference/ingest/*` (Security
Onion's own ingest pipeline definitions) plus live-captured real alerts --
see inline comments for what's confirmed vs. defensive. Windows/Sysmon
endpoint categories (process_creation, file_event, registry_*, etc.) and
Suricata/Zeek-shaped network alerts are covered by dedicated field
extraction. Cloud/identity/proxy sources this deployment also runs Sigma
rules against (Azure AD, AWS CloudTrail, GCP, Okta, M365, PaloAlto,
generic webserver/proxy logs -- confirmed live in so-detection, 2026-08-18)
are deliberately NOT given dedicated field mappings: none of their schemas
exist in so-alert-reference or any real captured fixture in this repo, and
guessing field names for a schema never verified against real data is
exactly what this project's fixture discipline prohibits. They still get
whatever the schema-agnostic IOC scanner below can find generically
(IPs/domains/URLs/hashes anywhere in the tree) -- just not a targeted
response-observable extraction. Extend `resolve_response_observables` for
one of these the same way the others were built: real captured alert
first, then code.

Output shape (TheHive 5, POST /api/v1/alert):
{
  "type": "...", "source": "...", "sourceRef": "...",
  "title": "...", "description": "...",
  "severity": 1-4, "tlp": 0-3, "pap": 0-3, "date": <epoch ms>,
  "tags": [...],
  "observables": [{"dataType": "domain", "data": "...", "ioc": true}, ...]
}
"""

import re
import json
import hashlib
import ipaddress
from collections import deque
from datetime import datetime, timezone
from urllib.parse import urlparse

# ==================================================================
# SECTION 1 -- IOC extraction (validated, noise-filtered, schema-agnostic)
# ==================================================================
IPV4_RE = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}'
    r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b'
)
IPV6_RE = re.compile(r'\b(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}\b')
URL_RE = re.compile(r'\b(?:https?|ftp)://[^\s"\'<>\\]+', re.IGNORECASE)
DOMAIN_RE = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
    r'[a-zA-Z]{2,24}\b'
)
SHA512_RE = re.compile(r'\b[a-fA-F0-9]{128}\b')
SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')
SHA1_RE   = re.compile(r'\b[a-fA-F0-9]{40}\b')
MD5_RE    = re.compile(r'\b[a-fA-F0-9]{32}\b')

# Suricata rule text (`rule.rule`) is NOT excluded from scanning -- it's a
# genuinely rich source of real IOCs: live-verified 2026-08-18 against this
# deployment's actual ruleset, real active ET rules embed the malware's
# current C2 domain directly in a content:"..." match (e.g.
# content:"arethqg.lat" for a live Lumma Stealer rule). But the SAME rule
# text also carries a `reference:md5,<hash>;` (or reference:url,.../
# reference:cve,...;) clause -- confirmed present on a large share of real
# rules in this deployment -- which is the rule AUTHOR's documentation
# citation ("this rule targets samples like this one"), not something
# observed in the CURRENT alert. Stripped before IOC regex matching so it
# never gets reported as an ioc:true hash/url as if it were freshly seen.
_RULE_REFERENCE_CLAUSE_RE = re.compile(r'reference:\s*[^;]*;', re.IGNORECASE)

# Suricata rule SYNTAX (keywords like `tls.sni;`, `flow:established,
# to_server;`, sticky buffers, flowbits names) is dot-shaped and gets
# false-positive-matched as a domain if the whole rule.rule text is
# scanned blindly -- live-verified 2026-08-18: "tls.sni" itself came out
# as a fake domain observable. The only part of Suricata rule syntax that
# represents a literal indicator string is a `content:"..."` clause (this
# is also exactly where the real Lumma Stealer C2 domains live in this
# deployment's actual ruleset). rule.rule scanning is restricted to just
# these clauses -- not scanning less, scanning the RIGHT part.
_CONTENT_CLAUSE_RE = re.compile(r'content:\s*"((?:[^"\\]|\\.)*)"', re.IGNORECASE)

EXCLUDE_PATH_SUBSTRINGS = [
    'policy.applied.artifacts', 'headers.', 'webhookurl', 'executionmode',
    # Suricata's `message` field is the raw eve.json alert re-serialized as a
    # JSON STRING (verified live 2026-08-17, event.module=suricata docs) --
    # every field in it is already mirrored in typed ECS fields (rule.*,
    # source.*, destination.*, network.transport), except for the embedded
    # base64 `packet` and decoded `payload_printable` blobs, which duplicate
    # network.data.decoded and are a major source of spurious hash/domain
    # regex matches. Scanning `message` adds noise, not coverage.
    'message',
    # `rule.reference` / `rule.references` is the ruleset VENDOR's own citation
    # link (e.g. https://community.emergingthreats.net), present on nearly
    # every ET/Snort-GPL rule. It is never attacker infrastructure -- without
    # this it gets reported as a true `ioc: true` observable on almost every
    # Suricata alert. Verified live against a real ET rule 2026-08-17.
    'reference',
    # `destination.as.network` / `source.as.network` is an ASN CIDR range
    # (e.g. "54.36.0.0/14", verified live 2026-08-17), not a host IP -- the
    # IP regex has no CIDR awareness and was extracting the network address
    # as a fake single-host external-IP observable.
    '.as.network',
    # `import.id` / `import.file` are Security Onion's own internal
    # PCAP-import tracking fields (so-import-pcap), not attacker data --
    # import.id is a 32-hex-char batch id that was being misread as an MD5.
    # The SAME batch id is also embedded a second time inside
    # `log.file.path` (e.g. /nsm/import/<batch-id>/suricata/eve-*.json,
    # verified live 2026-08-17) -- filebeat's own file-tracking metadata,
    # not attacker-controlled content, for any engine.
    'import.', 'log.file.path',
    # ECS/SO plumbing values that are dot-shaped and were false-positive-
    # matched as domains once the TLD allowlist was removed (live-verified
    # 2026-08-18: event.dataset="suricata.alert"/"sigma.alert",
    # data_stream.dataset="endpoint.events.process", and raw index names
    # like ".ds-logs-endpoint.events.process-default-..." all came out as
    # fake domain observables). These are schema/infrastructure
    # identifiers, never attacker-controlled content, for any engine.
    'event.dataset', 'data_stream.', '_index', 'metadata.raw_index',
    'metadata.pipeline', 'metadata.index', 'metadata.type',
    # `ioc.*` is a custom development-time ingest addition, NOT a real
    # Security Onion field -- this repo's own CLAUDE.md documents it as
    # "present but never read" and directs never building on it. The same
    # policy applies to scanning it: verified live 2026-08-18, ioc.dataset
    # ("sigma.alert") was coming through as a fake domain observable.
    'ioc.',
    # A generic beats/elastic-agent pipeline `tags` array (e.g.
    # ["elastic-agent","input-nodemanager","events.process"]) -- verified
    # live 2026-08-18, "events.process" (one of these tag strings) was
    # coming through as a fake domain. Infrastructure labels, not
    # attacker-controlled content, for any engine.
    'tags',
]

# Deliberately NOT a TLD allowlist (see add_domain_if_valid) -- a small,
# CLOSED set of Windows executable/script extensions that are never real
# gTLDs/ccTLDs, used only to reject the specific false-positive pattern
# live-verified 2026-08-18 (command-line text like
# "...Temp\xordump.exe" producing a fake "xordump.exe" domain). Excludes
# ambiguous ones on purpose: "com" is a real, huge gTLD (and the historical
# DOS-executable extension is effectively extinct), so it is NOT in this
# set -- dropping real .com domains would be a far worse regression than
# occasionally missing a *.com executable reference.
_NON_DOMAIN_EXECUTABLE_SUFFIXES = {
    'exe', 'dll', 'sys', 'bat', 'cmd', 'ps1', 'vbs', 'vbe', 'msi', 'scr',
    'cpl', 'msc', 'jar', 'wsf', 'wsh',
}

IMPHASH_KEYS = {'imphash', 'imp_hash', 'importhash', 'import_hash',
                'peimphash', 'pe_imphash'}

_REFANG_PATTERNS = [
    (re.compile(r'\[\.\]|\(\.\)|\{\.\}'), '.'),
    (re.compile(r'\[:\]|\(:\)'), ':'),
    (re.compile(r'hxxps', re.IGNORECASE), 'https'),
    (re.compile(r'hxxp', re.IGNORECASE), 'http'),
]


def refang(text):
    for pattern, replacement in _REFANG_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def get_path(obj, dotted_path):
    cur = obj
    for part in dotted_path.split('.'):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


def first_non_empty(*values):
    for v in values:
        if v not in (None, '', [], {}):
            return v
    return None


def find_all_dicts_by_key(obj, target_key):
    """BFS: ALL dict values assigned to a key named target_key, anywhere
    in the tree (ECS/beats data splits one concept across sibling blocks
    at different depths, so a single dotted-path lookup can miss it)."""
    target_key = target_key.lower()
    matches = []
    queue = deque([obj])
    while queue:
        cur = queue.popleft()
        if isinstance(cur, dict):
            for k, v in cur.items():
                if k.lower() == target_key and isinstance(v, dict):
                    matches.append(v)
            for v in cur.values():
                if isinstance(v, (dict, list)):
                    queue.append(v)
        elif isinstance(cur, list):
            for v in cur:
                if isinstance(v, (dict, list)):
                    queue.append(v)
    return matches


def unwrap_webhook(alert):
    """Strip the n8n Webhook transport wrapper if present. No-op otherwise."""
    if isinstance(alert, dict) and isinstance(alert.get('body'), dict) and (
        'headers' in alert or 'webhookUrl' in alert or 'executionMode' in alert
    ):
        return alert['body']
    return alert


def scan_strings(alert):
    stack = [("", alert)]
    while stack:
        path, cur = stack.pop()
        low_path = path.lower()
        if any(bad in low_path for bad in EXCLUDE_PATH_SUBSTRINGS):
            continue
        if isinstance(cur, dict):
            for k, v in cur.items():
                stack.append((f"{path}.{k}" if path else str(k), v))
        elif isinstance(cur, list):
            for i, v in enumerate(cur):
                stack.append((f"{path}[{i}]", v))
        elif isinstance(cur, str) and cur.strip():
            key_name = path.rsplit('.', 1)[-1].split('[')[0].lower()
            yield path, key_name, cur


def classify_ip(candidate):
    try:
        ip_obj = ipaddress.ip_address(candidate)
    except ValueError:
        return None
    if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or
            ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified):
        return 'internal'
    return 'external'


def add_domain_if_valid(candidate, domains_set):
    """No hardcoded TLD allowlist -- deliberately removed. A fixed list of
    ~150 TLDs was silently DROPPING real, currently-active malicious
    domains: live-verified 2026-08-18 against this deployment's actual
    ruleset (so-detection), real ET rules alert on Lumma Stealer C2 domains
    on .lat/.cyou/.shop TLDs -- .lat was not in the old list, so that exact
    domain would never have become an observable. There are 1000+ real
    gTLDs/ccTLDs today and the list can only ever go stale; validating
    structure (label syntax/length, alphabetic TLD shape, not a bare IP)
    instead of TLD membership is the only way to not silently miss
    whatever TLD a malicious domain happens to be registered on.
    Trade-off: this is looser than a curated list, so it will occasionally
    flag a non-domain, TLD-shaped token from free text (e.g. a file
    extension). Acceptable here because the input is structured detection-
    engine field values, not free-flowing prose."""
    candidate = candidate.strip().strip('.').lower()
    if not candidate or '.' not in candidate or len(candidate) > 253:
        return
    if classify_ip(candidate) is not None:
        return
    labels = candidate.split('.')
    if any(len(lbl) == 0 or len(lbl) > 63 for lbl in labels):
        return
    if any(lbl.startswith('-') or lbl.endswith('-') for lbl in labels):
        return
    if labels[-1] in _NON_DOMAIN_EXECUTABLE_SUFFIXES:
        return
    domains_set.add(candidate)


def clean_url(raw_url):
    return raw_url.rstrip('\'",;:.)]}')


def normalize_ip_list(raw):
    if raw is None:
        return []
    values = raw if isinstance(raw, list) else [raw]
    out = []
    for v in values:
        if isinstance(v, str):
            try:
                ipaddress.ip_address(v)
                out.append(v)
            except ValueError:
                continue
    return out


def extract_context(alert, source_engine):
    """hostname/host_ip resolution is engine-aware on purpose.

    `metadata.input.beats.host.ip` (and any dict keyed "host" found by the
    blind BFS fallback) is the IP of whichever machine is RUNNING the beats/
    elastic-agent shipper. For Sigma/YARA alerts (EDR telemetry: dataset
    endpoint.events.*) that shipper runs ON the monitored endpoint, so it IS
    the host's own IP -- legitimate. For Suricata (NIDS network alerts) that
    shipper runs on the passive SO sensor box, which is not one of the hosts
    in the flow being alerted on -- using it as "the host" is a real bug
    (verified live 2026-08-17: a real alert's title showed a fabricated
    "unknown-host (172.20.24.40)", where .40 was just the sensor's own
    management IP, not anything from the actual network flow). Suricata
    alerts have no single "host" concept at all -- they have a source/dest
    flow, resolved separately via resolve_network_flow().
    """
    hostname = first_non_empty(
        get_path(alert, 'host.name'), get_path(alert, 'host.hostname'),
        get_path(alert, 'event_data.host.name'),
        get_path(alert, 'event_data.host.hostname'),
        get_path(alert, 'winlog.computer_name'),
        get_path(alert, 'event_data.winlog.computer_name'),
    )
    host_ip_raw = first_non_empty(
        get_path(alert, 'host.ip'), get_path(alert, 'event_data.host.ip'),
        None if source_engine == 'suricata' else
        get_path(alert, 'event_data.metadata.input.beats.host.ip'),
    )
    agent_id = first_non_empty(
        get_path(alert, 'agent.id'), get_path(alert, 'event_data.agent.id'),
        get_path(alert, 'elastic.agent.id'),
        get_path(alert, 'event_data.elastic.agent.id'),
        get_path(alert, 'elastic_agent.id'),
        get_path(alert, 'event_data.elastic_agent.id'),
    )
    if source_engine != 'suricata' and (hostname is None or not host_ip_raw):
        host_blocks = find_all_dicts_by_key(alert, 'host')
        if hostname is None:
            for hb in host_blocks:
                hostname = first_non_empty(
                    hb.get('name'), hb.get('hostname'), hb.get('computer_name'),
                )
                if hostname:
                    break
        if not host_ip_raw:
            for hb in host_blocks:
                if hb.get('ip'):
                    host_ip_raw = hb['ip']
                    break
    if agent_id is None:
        for ab in find_all_dicts_by_key(alert, 'agent'):
            if ab.get('id'):
                agent_id = ab['id']
                break
    sensor_name = get_path(alert, 'observer.name') if source_engine == 'suricata' else None
    return hostname, normalize_ip_list(host_ip_raw), agent_id, sensor_name


def resolve_network_flow(alert):
    """The flow identity for any network-behavior alert -- Suricata NIDS,
    or a Zeek-backed Sigma rule (lateral movement, SMB/RDP anomalies), both
    of which use the same source.ip/destination.ip/network.transport ECS
    shape. Real field names verified live 2026-08-17 against a real
    suricata.alert doc -- NOT the flat src_ip/dest_ip/proto that only
    exist in the raw, un-normalized eve.json (nested inside `message`,
    excluded from scanning above).

    Checks the top-level path first (the confirmed-real shape), then falls
    back to a deep tree search (find_all_dicts_by_key) for alerts that
    nest source/destination differently -- e.g. under event_data for some
    Sigma rule shapes -- rather than only ever looking in one hardcoded
    spot."""
    src = get_path(alert, 'source.ip')
    dst = get_path(alert, 'destination.ip')
    proto = get_path(alert, 'network.transport')

    if src is None:
        for block in find_all_dicts_by_key(alert, 'source'):
            if block.get('ip'):
                src = block['ip']
                break
    if dst is None:
        for block in find_all_dicts_by_key(alert, 'destination'):
            if block.get('ip'):
                dst = block['ip']
                break
    if proto is None:
        for block in find_all_dicts_by_key(alert, 'network'):
            if block.get('transport'):
                proto = block['transport']
                break

    if not src or not dst:
        return None, None, None
    return src, dst, proto



# Suricata's `classtype` token is never promoted to a top-level ECS field by
# this deployment's pipeline (so-alert-reference/ingest/suricata.alert) --
# only `rule.category` (human text, always present) is. This maps the
# standard Suricata/Snort classification.config categories (a fixed,
# canonical list, not deployment-specific) to which side of the flow is
# more likely "the attacker" when one side is internal -- used only to
# label the internal-IP response observable, never to change ioc:true/false
# on the external IP (that already follows classify_ip regardless).
SURICATA_CATEGORY_ROLE = {
    "a network trojan was detected": "source_is_victim",  # internal host beaconing to external C2
    "attempted administrator privilege gain": "source_is_attacker",
    "attempted user privilege gain": "source_is_attacker",
    "web application attack": "source_is_attacker",
    "attempted denial of service": "source_is_attacker",
    "denial of service": "source_is_attacker",
    "detection of a network scan": "source_is_attacker",
    "attempted information leak": "source_is_attacker",
    "misc attack": "source_is_attacker",
    "suspicious login": "source_is_attacker",
    "default login attempt": "source_is_attacker",
}
# Verified live 2026-08-18 against this deployment's ACTUAL active ruleset
# (so-detection index, so_detection.engine="suricata", ~600-rule sample
# across two slices): classtype distribution is dominated by
# trojan-activity (187), exploit-kit (57), domain-c2 (51), misc-attack
# (292 in a separate slice -- generic/ambiguous, deliberately left
# unmapped so it falls through to the safe both-sides-tagged default),
# plus social-engineering, attempted-admin. exploit-kit/domain-c2/
# social-engineering all follow the same pattern as trojan-activity: an
# internal host reaching OUT to malicious external infrastructure --
# real examples pulled live: ET rules alerting on internal hosts doing
# TLS SNI / DNS lookups for Lumma Stealer C2 domains (arethqg.lat,
# deckerh.cyou), classtype:domain-c2.
_SURICATA_CLASSTYPE_ROLE = {
    "trojan-activity": "source_is_victim",
    "domain-c2": "source_is_victim",
    "exploit-kit": "source_is_victim",
    "social-engineering": "source_is_victim",
    "attempted-admin": "source_is_attacker",
    "attempted-user": "source_is_attacker",
    "web-application-attack": "source_is_attacker",
    "attempted-dos": "source_is_attacker",
    "denial-of-service": "source_is_attacker",
    "attempted-recon": "source_is_attacker",
    "network-scan": "source_is_attacker",
    "suspicious-login": "source_is_attacker",
    "default-login-attempt": "source_is_attacker",
}
_CLASSTYPE_RE = re.compile(r'classtype:\s*([a-z0-9\-]+)', re.IGNORECASE)


def resolve_suricata_role(alert):
    """'source_is_attacker' / 'source_is_victim' / None (ambiguous/unknown
    category -- caller should tag both sides generically in that case)."""
    category = get_path(alert, 'rule.category')
    if isinstance(category, str) and category.lower() in SURICATA_CATEGORY_ROLE:
        return SURICATA_CATEGORY_ROLE[category.lower()]
    rule_text = get_path(alert, 'rule.rule')
    if isinstance(rule_text, str):
        m = _CLASSTYPE_RE.search(rule_text)
        if m:
            return _SURICATA_CLASSTYPE_ROLE.get(m.group(1).lower())
    return None


def extract_iocs(alert: dict, source_engine: str) -> dict:
    """Extract threat-intel-ready IOCs from a single alert of ANY shape."""
    if not isinstance(alert, dict):
        alert = {}
    alert = unwrap_webhook(alert)

    hostname, host_ips, agent_id, sensor_name = extract_context(alert, source_engine)
    local_ips = set(host_ips)

    external_ips, domains, urls = set(), set(), set()
    md5s, sha1s, sha256s, sha512s, imphashes = set(), set(), set(), set(), set()

    for _path, key_name, raw_text in scan_strings(alert):
        text = refang(raw_text)
        text = _RULE_REFERENCE_CLAUSE_RE.sub('', text)
        if key_name == 'rule':
            # rule.rule is Suricata rule SYNTAX, not free text -- only
            # content:"..." clauses are literal indicator strings; the
            # rest (keywords, sticky buffers, flowbits) is not scannable
            # content and is a reliable source of false positives (see
            # _CONTENT_CLAUSE_RE's docstring above).
            text = ' '.join(_CONTENT_CLAUSE_RE.findall(text))
        for m in URL_RE.finditer(text):
            url = clean_url(m.group(0))
            urls.add(url)
            try:
                host = urlparse(url).hostname
            except ValueError:
                host = None
            if host:
                cls = classify_ip(host)
                if cls == 'external':
                    external_ips.add(host)
                elif cls is None:
                    add_domain_if_valid(host, domains)
        for pattern in (IPV4_RE, IPV6_RE):
            for m in pattern.finditer(text):
                ip = m.group(0)
                if classify_ip(ip) == 'external' and ip not in local_ips:
                    external_ips.add(ip)
        for m in DOMAIN_RE.finditer(text):
            # PowerShell type-accelerator syntax ([Net.ServicePointManager],
            # [Net.SecurityProtocolType]) is dot-shaped and matches the same
            # pattern as a domain -- verified live 2026-08-18 against the
            # real Sigma fixture's command_line/args text. Structurally
            # distinct from a real domain: always wrapped in [...] in
            # PowerShell syntax, which a domain never is.
            before = text[m.start() - 1] if m.start() > 0 else ''
            after = text[m.end()] if m.end() < len(text) else ''
            if before == '[' or after == ']':
                continue
            add_domain_if_valid(m.group(0), domains)
        for m in SHA512_RE.finditer(text):
            sha512s.add(m.group(0).lower())
        for m in SHA256_RE.finditer(text):
            sha256s.add(m.group(0).lower())
        for m in SHA1_RE.finditer(text):
            sha1s.add(m.group(0).lower())
        for m in MD5_RE.finditer(text):
            val = m.group(0).lower()
            if key_name in IMPHASH_KEYS:
                imphashes.add(val)
            else:
                md5s.add(val)

    external_ips -= local_ips  # never report the endpoint's own IP as external

    def list_or_false(sorted_list):
        return sorted_list if sorted_list else False

    return {
        "hostname": {"value": hostname if hostname else "unknown", "found": bool(hostname)},
        "host_ip": list_or_false(sorted(host_ips)),
        "agent_id": {"value": agent_id if agent_id else "unknown", "found": bool(agent_id)},
        "sensor_name": sensor_name,
        "external_ips": list_or_false(sorted(external_ips)),
        "domains": list_or_false(sorted(domains)),
        "urls": list_or_false(sorted(urls)),
        "hashes": {
            "md5": list_or_false(sorted(md5s)),
            "sha1": list_or_false(sorted(sha1s)),
            "sha256": list_or_false(sorted(sha256s)),
            "sha512": list_or_false(sorted(sha512s)),
            "imphash": list_or_false(sorted(imphashes)),
        },
    }


# ==================================================================
# SECTION 2 -- Alert metadata resolution (engine, severity, rule, time)
# ==================================================================
SEVERITY_LABEL_MAP = {
    'informational': 1, 'info': 1, 'low': 1,
    'medium': 2, 'moderate': 2,
    'high': 3,
    'critical': 4, 'severe': 4,
}
SURICATA_SEVERITY_MAP = {1: 4, 2: 3, 3: 2}  # Suricata's own scale is inverted

DEFAULT_TLP = 2   # 0=white/clear, 1=green, 2=amber, 3=red
DEFAULT_PAP = 2   # same 0-3 scale, permissible-actions protocol


def detect_source_engine(alert):
    explicit = first_non_empty(
        get_path(alert, 'ioc.source_engine'),
        get_path(alert, 'event.module'),
    )
    if isinstance(explicit, str) and explicit.lower() in ('sigma', 'suricata', 'yara'):
        return explicit.lower()
    # Strelka is a documented SO integration (so-alert-reference/ingest/
    # strelka.file) with zero live evidence in this deployment (no index,
    # no captured alert) -- what event.module it actually sets is NOT in
    # that reference dump. Assumed "strelka" by the same naming convention
    # as "suricata", flagged as the one unconfirmed field name in this
    # extension. Falls back to the raw-shape heuristic below regardless.
    if isinstance(explicit, str) and explicit.lower() == 'strelka':
        return 'yara'

    if get_path(alert, 'sigma_level') is not None or find_all_dicts_by_key(alert, 'rule'):
        if get_path(alert, 'alert.signature') is None:
            return 'sigma'

    if (get_path(alert, 'alert.signature') is not None or
            (alert.get('src_ip') is not None and alert.get('dest_ip') is not None)):
        return 'suricata'

    if alert.get('rule_name') is not None or 'strings' in alert or 'meta' in alert:
        return 'yara'

    return 'unknown'


def resolve_rule_name(alert):
    return first_non_empty(
        get_path(alert, 'rule.name'),
        get_path(alert, 'ioc.rule.name'),
        get_path(alert, 'alert.signature'),
        alert.get('rule_name'),
        "Unnamed detection",
    )


def resolve_rule_uuid(alert):
    return first_non_empty(
        get_path(alert, 'rule.uuid'),
        get_path(alert, 'ioc.rule.uuid'),
        get_path(alert, 'alert.signature_id'),
    )


def resolve_severity(alert, source_engine):
    label = first_non_empty(
        get_path(alert, 'sigma_level'),
        get_path(alert, 'event.severity_label'),
        get_path(alert, 'ioc.rule.severity'),
    )
    if label is None:
        for _p, key_name, value in scan_strings(alert):
            if key_name in ('severity_label', 'sigma_level'):
                label = value
                break
    if isinstance(label, str) and label.lower() in SEVERITY_LABEL_MAP:
        return SEVERITY_LABEL_MAP[label.lower()]

    if source_engine == 'suricata':
        sur_sev = get_path(alert, 'alert.severity')
        if isinstance(sur_sev, int) and sur_sev in SURICATA_SEVERITY_MAP:
            return SURICATA_SEVERITY_MAP[sur_sev]

    return 2  # unknown severity -> Medium; safer than silently picking Low


def resolve_timestamp_ms(alert):
    ts = first_non_empty(
        get_path(alert, '@timestamp'),
        get_path(alert, 'event_data.@timestamp'),
        get_path(alert, 'timestamp'),
    )
    if isinstance(ts, str):
        try:
            cleaned = ts.replace('Z', '+00:00')
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1000)
        except ValueError:
            pass
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def resolve_source_ref(alert, hostname, rule_uuid, timestamp_ms):
    """TheHive requires (type, source, sourceRef) to be unique per alert.
    Prefer a natural id already in the data (Elastic doc _id) so replays
    of the SAME upstream event map to the SAME TheHive alert instead of
    creating duplicates; fall back to a deterministic hash otherwise."""
    natural_id = first_non_empty(alert.get('_id'), get_path(alert, 'event_data._id'))
    if natural_id:
        return str(natural_id)
    basis = f"{rule_uuid}|{hostname}|{timestamp_ms}".encode('utf-8')
    return hashlib.sha256(basis).hexdigest()[:24]


def resolve_context_line(alert, source_engine):
    """One short line of extra context for the description, engine-specific."""
    if source_engine == 'sigma':
        cmd = get_path(alert, 'event_data.process.command_line')
        parent_cmd = get_path(alert, 'event_data.process.parent.command_line')
        lines = []
        if cmd:
            lines.append(f"Command line: {cmd}")
        if parent_cmd and parent_cmd != cmd:
            lines.append(f"Parent command line: {parent_cmd}")
        return "\n".join(lines) if lines else None
    if source_engine == 'suricata':
        src, dst, proto = resolve_network_flow(alert)
        if src and dst:
            return f"Flow: {src} -> {dst} ({proto or 'unknown proto'})"
        return None
    if source_engine == 'yara':
        strings = alert.get('strings')
        if isinstance(strings, list) and strings:
            return f"Matched string (1 of {len(strings)}): {strings[0]}"
        return None
    return None


# ==================================================================
# SECTION 3 -- tags (endpoint/asset context) & observables (IOCs only)
# ==================================================================
def build_tags(source_engine, rule_name, hostname, host_ips, agent_id, sensor_name=None, community_id=None):
    """hostname / host_ip / agent_id live HERE as separate tags, never in observables."""
    tags = [f"engine:{source_engine}", "security-onion"]

    if rule_name and rule_name != "Unnamed detection":
        tags.append(f"rule:{rule_name}")

    if agent_id:
        tags.append(f"agent-id:{agent_id}")

    if sensor_name:
        tags.append(f"sensor:{sensor_name}")

    if community_id:
        tags.append(f"flow:{community_id}")

    # Add hostname as its own separate string (without prefix)
    if hostname:
        tags.append(hostname)

    # Add IP address(es) as separate strings without the "ip:" prefix
    if host_ips:
        if isinstance(host_ips, str):
            tags.append(host_ips)
        else:
            tags.extend(host_ips)

    # Return ONLY a flat list of strings (required by TheHive API)
    return sorted(set(tags))


def build_observables(iocs):
    """Observables built ONLY from actual IOCs -- external IPs, domains,
    URLs, hashes. hostname/host_ip/agent_id are NEVER included here.

    Every observable carries an re&ct:<category> tag (network for ip/domain/
    url, file for hash) alongside the existing algo tag, engine-agnostic --
    a hash is "file" category and an IP is "network" category regardless of
    which detection engine (Suricata/Sigma/YARA) flagged it. This also
    covers the YARA/Strelka file-hash case: Strelka's real field names
    (hash.sha256/hash.md5, per so-alert-reference/ingest/strelka.file) are
    plain string values the scan_strings-based extractor above already
    catches correctly with ioc:true -- no separate YARA resolver needed."""
    observables = []
    for ip in (iocs['external_ips'] or []):
        observables.append({"dataType": "ip", "data": ip, "ioc": True, "tags": ["re&ct:network"]})
    for d in (iocs['domains'] or []):
        observables.append({"dataType": "domain", "data": d, "ioc": True, "tags": ["re&ct:network"]})
    for u in (iocs['urls'] or []):
        observables.append({"dataType": "url", "data": u, "ioc": True, "tags": ["re&ct:network"]})
    hashes = iocs['hashes']
    for h in (hashes['md5'] or []):
        observables.append({"dataType": "hash", "data": h, "ioc": True, "tags": ["md5", "re&ct:file"]})
    for h in (hashes['sha1'] or []):
        observables.append({"dataType": "hash", "data": h, "ioc": True, "tags": ["sha1", "re&ct:file"]})
    for h in (hashes['sha256'] or []):
        observables.append({"dataType": "hash", "data": h, "ioc": True, "tags": ["sha256", "re&ct:file"]})
    for h in (hashes['sha512'] or []):
        observables.append({"dataType": "hash", "data": h, "ioc": True, "tags": ["sha512", "re&ct:file"]})
    for h in (hashes['imphash'] or []):
        # Not a file hash -- don't submit to VT/etc. as one. ioc=False keeps
        # it from being treated as a straightforward malicious-hash lookup.
        observables.append({"dataType": "hash", "data": h, "ioc": False, "tags": ["imphash", "re&ct:file"]})
    return observables


def _network_flow_response_observables(alert, source_engine):
    """Network-category response observables shared by Suricata NIDS
    alerts AND Zeek-backed Sigma network-behavior rules (lateral movement,
    SMB/RDP anomalies -- same source.ip/destination.ip/network.transport
    shape, see resolve_network_flow). Adds the INTERNAL side of the flow
    (never the external one -- that's already an IOC observable above),
    the targeted port, and the ASN of whichever side is EXTERNAL (not
    hardcoded to "destination" -- an inbound attack alert puts the
    attacker's ASN on the SOURCE side instead).

    Role tagging (attacker/victim/target/c2) via resolve_suricata_role()
    only applies for source_engine=='suricata' -- Sigma has no equivalent
    classification scheme, so its internal IP(s) get a generic
    re&ct:network tag with no role guess rather than a wrong one."""
    observables = []
    src, dst, _proto = resolve_network_flow(alert)
    if not src or not dst:
        return observables

    role = resolve_suricata_role(alert) if source_engine == 'suricata' else None
    for ip, is_source in ((src, True), (dst, False)):
        if classify_ip(ip) != 'internal':
            continue
        role_tag = None
        if role == 'source_is_attacker':
            role_tag = 'role:attacker' if is_source else 'role:target'
        elif role == 'source_is_victim':
            role_tag = 'role:victim' if is_source else 'role:c2'
        tags = ["re&ct:network"] + ([role_tag] if role_tag else [])
        observables.append({"dataType": "ip", "data": ip, "ioc": False, "tags": tags})

    dest_port = get_path(alert, 'destination.port')
    if dest_port is not None:
        observables.append({
            "dataType": "other", "data": str(dest_port), "ioc": False,
            "tags": ["re&ct:network", "field:destination.port"],
        })

    # source.hostname/destination.hostname -- confirmed real fields, Sysmon
    # network_connection events (so-alert-reference/ingest/sysmon, renamed
    # from winlog.event_data.SourceHostname/DestinationHostname). Many
    # internal Windows hostnames have no dot (e.g. "WORKSTATION-05"), so
    # the generic domain scanner never catches them -- this is the only
    # path that does.
    for side in ('source', 'destination'):
        host = get_path(alert, f'{side}.hostname')
        if host:
            observables.append({
                "dataType": "hostname", "data": host, "ioc": False,
                "tags": ["re&ct:network", f"field:{side}.hostname"],
            })

    for ip, side in ((src, 'source'), (dst, 'destination')):
        if classify_ip(ip) == 'external':
            as_number = get_path(alert, f'{side}.as.number')
            if as_number is not None:
                observables.append({
                    "dataType": "autonomous-system", "data": f"AS{as_number}", "ioc": True,
                    "tags": ["re&ct:network"],
                })
    return observables


def _first_code_signature(block):
    """`block` is a process or process.parent dict. code_signature is
    real, live-verified in TWO shapes in this deployment's actual EDR data
    (both present simultaneously on the same real Sigma alert): a single
    dict at process.code_signature, and a list at process.Ext.code_signature
    (Elastic Endpoint's own Ext.* convention). Checks the simpler dict
    shape first, falls back to the first list entry. Returns None if
    neither is present."""
    cs = block.get('code_signature')
    if isinstance(cs, dict):
        return cs
    ext = block.get('Ext')
    if isinstance(ext, dict):
        cs_list = ext.get('code_signature')
        if isinstance(cs_list, list) and cs_list and isinstance(cs_list[0], dict):
            return cs_list[0]
    return None


def _sigma_response_observables(alert, hostname, host_ips, agent_id):
    """Process/Identity/Configuration response observables for Sigma
    (EDR/Sysmon-sourced, per so-alert-reference/ingest/sysmon). None carry
    independent TI-lookup value -- they're the handles a responder (EDR
    isolate, kill process, disable account) needs to act on this specific
    event, not indicators to check against a reputation feed.

    Uses find_all_dicts_by_key (deep BFS over the whole tree) rather than
    one or two hardcoded dotted paths -- ECS/Sysmon data nests "process"/
    "user"/"registry"/"host" at varying depths depending on event type and
    Sigma rule shape, so a fixed event_data.X path silently misses data
    whenever the nesting differs even slightly. This deliberately trades
    the "exactly which one path" precision of an earlier version for
    actually finding the data wherever it lives -- the same principle the
    original IOC scanner already used for hash/IP/domain/URL extraction."""
    observables = []
    by_key = {}

    def add(data_type, data, tags):
        # A single literal value observed in two different ROLES (e.g. a
        # nested powershell.exe spawning another powershell.exe -- child
        # and parent executable are the identical string) must merge onto
        # ONE observable with both field: tags, not silently drop the
        # second occurrence -- verified live 2026-08-18 against the real
        # Sigma fixture, where this exact case dropped the parent-process
        # executable entirely.
        if data is None or data == '':
            return
        data = str(data)
        key = (data_type, data)
        if key in by_key:
            existing = by_key[key]
            for t in tags:
                if t not in existing["tags"]:
                    existing["tags"].append(t)
            return
        entry = {"dataType": data_type, "data": data, "ioc": False, "tags": list(tags)}
        by_key[key] = entry
        observables.append(entry)

    if hostname:
        add("hostname", hostname, ["re&ct:process"])
    if agent_id:
        # EDR APIs (Elastic Defend, most others) isolate/query by the
        # agent's own id, not by hostname -- the actual handle a
        # responder's isolate-host action needs.
        add("other", agent_id, ["re&ct:process", "field:agent.id"])
    for ip in (host_ips or []):
        add("ip", ip, ["re&ct:process", "field:host.ip"])

    # Any "host" block anywhere -- host.id (the EDR agent's durable
    # machine identifier, distinct from and more stable than hostname)
    # lives alongside host.name in the real Sigma fixture's event_data.host.
    for hb in find_all_dicts_by_key(alert, 'host'):
        hid = hb.get('id')
        add("other", hid, ["re&ct:process", "field:host.id"])

    # Any "process" block anywhere in the tree -- covers the triggering
    # process AND, via its own "parent" sub-dict, the parent process.
    # Parent PID is process.ppid in this deployment's real sysmon pipeline
    # mapping (so-alert-reference/ingest/sysmon), NOT process.parent.pid
    # (the ECS-official convention) -- checked as a fallback since a
    # future SO version could map it either way.
    for proc in find_all_dicts_by_key(alert, 'process'):
        entity_id = proc.get('entity_id')
        pid = proc.get('pid')
        add("other", entity_id or pid,
            ["re&ct:process", "field:process.entity_id" if entity_id else "field:process.pid"])
        add("filename", proc.get('executable'), ["re&ct:process", "field:process.executable"])
        add("other", proc.get('working_directory'),
            ["re&ct:process", "field:process.working_directory"])

        # Code-signing identity is only surfaced when the signature is NOT
        # trusted -- a legitimately Microsoft-signed binary shows up on
        # nearly every alert and would be pure noise as an observable;
        # an untrusted/unsigned/spoofed signer is a genuine hunting pivot
        # ("find every other binary signed by this same likely-stolen
        # cert"). Computed before the pe.* block below since company/
        # product are gated on the same trust check.
        cs = _first_code_signature(proc)
        untrusted = bool(cs) and not cs.get('trusted', True)
        if untrusted and cs.get('subject_name'):
            add("other", cs['subject_name'],
                ["re&ct:process", "field:process.code_signature.subject_name", "untrusted-signature"])

        # PE-internal claimed filename vs the actual on-disk path --
        # classic LOLBin/masquerading signal when they don't match (e.g.
        # a file named "notepad.exe" whose PE header claims
        # "PowerShell.EXE"). Real fields, live-verified in this
        # deployment's actual EDR data (process.pe.original_file_name/
        # .company/.product, so-alert-reference/ingest/sysmon). company/
        # product are gated the same as code_signature.subject_name --
        # "Microsoft Corporation" on every legitimate Windows binary would
        # otherwise be noise on nearly every alert; what a binary CLAIMS
        # to be only matters once its signature is already suspect.
        pe = proc.get('pe')
        if isinstance(pe, dict):
            if pe.get('original_file_name'):
                orig_name = pe['original_file_name']
                exe_basename = (proc.get('executable') or '').replace('\\', '/').rsplit('/', 1)[-1]
                tags = ["re&ct:process", "field:process.pe.original_file_name"]
                if exe_basename and orig_name.lower() != exe_basename.lower():
                    tags.append("masquerading-suspected")
                add("other", orig_name, tags)
            if untrusted:
                for key in ('company', 'product'):
                    val = pe.get(key)
                    if val:
                        add("other", val, ["re&ct:process", f"field:process.pe.{key}", "untrusted-signature"])

        parent = proc.get('parent')
        if isinstance(parent, dict):
            p_entity_id = parent.get('entity_id')
            p_pid = first_non_empty(parent.get('pid'), proc.get('ppid'))
            add("other", p_entity_id or p_pid,
                ["re&ct:process", "field:process.parent.entity_id" if p_entity_id else "field:process.parent.pid"])
            add("filename", parent.get('executable'), ["re&ct:process", "field:process.parent.executable"])

            p_cs = _first_code_signature(parent)
            if p_cs and p_cs.get('subject_name') and not p_cs.get('trusted', True):
                add("other", p_cs['subject_name'],
                    ["re&ct:process", "field:process.parent.code_signature.subject_name", "untrusted-signature"])

    # Any "user" block anywhere -- Windows events can carry more than one
    # distinct user concept (e.g. Subject vs Target in account-management
    # events); each becomes its own observable rather than assuming there
    # is exactly one. The SID (user.id) is more durable/unambiguous than
    # the display name (survives renames, unique across domains) and is
    # what most EDR/AD tooling actually keys on.
    for user in find_all_dicts_by_key(alert, 'user'):
        name = user.get('name')
        if name:
            domain = user.get('domain')
            add("other", f"{domain}\\{name}" if domain else name,
                ["re&ct:identity", "field:user.name"])
        add("other", user.get('id'), ["re&ct:identity", "field:user.id"])

    # Defensive: registry.* is a real ECS field group with a mapped index
    # template in this deployment (templates/ecs/registry.json), but zero
    # confirmed presence in any real alert seen so far -- deep search, so
    # it silently no-ops if absent regardless of nesting depth.
    for reg in find_all_dicts_by_key(alert, 'registry'):
        path = reg.get('path')
        if path:
            value = reg.get('value')
            add("registry", f"{path} = {value}" if value else path, ["re&ct:configuration"])

    # file.target -- confirmed real field, Sysmon file_create/file_delete/
    # raw_file_access_read categories (so-alert-reference/ingest/sysmon,
    # renamed from winlog.event_data.TargetFilename). Shares
    # _file_identity_pairs with YARA/Strelka below since both populate the
    # same "file" dict shape, just different leaf keys.
    for data, tags in _file_identity_pairs(alert):
        add("filename", data, tags)

    return observables


def _file_identity_pairs(alert):
    """(data, tags) pairs for any "file" block anywhere in the tree --
    shared between Sigma (file.target, Sysmon file_event/file_delete/
    raw_file_access_read categories per so-alert-reference/ingest/sysmon)
    and YARA/Strelka (file.name/file.source/file.directory per
    so-alert-reference/ingest/strelka.file). Different engines populate
    different leaf keys on the same "file" dict shape -- deep search
    (find_all_dicts_by_key) so this doesn't depend on which one."""
    pairs = []
    for f in find_all_dicts_by_key(alert, 'file'):
        name = f.get('name')
        if name:
            pairs.append((name, ["re&ct:file"]))
        target = f.get('target')
        if target:
            pairs.append((target, ["re&ct:file", "field:file.target"]))
        full_path = first_non_empty(
            f.get('source'),
            f"{f['directory']}/{name}" if f.get('directory') and name else None,
        )
        if full_path:
            pairs.append((full_path, ["re&ct:file", "field:file.path"]))
    return pairs


def _yara_response_observables(alert):
    """File-identity response observables for YARA/Strelka: the scanned
    file's name and full original path -- see _file_identity_pairs for the
    real field names (so-alert-reference/ingest/strelka.file)."""
    observables = []
    by_data = {}

    def add(data, tags):
        if not data:
            return
        if data in by_data:
            existing = by_data[data]
            for t in tags:
                if t not in existing["tags"]:
                    existing["tags"].append(t)
            return
        entry = {"dataType": "filename", "data": data, "ioc": False, "tags": list(tags)}
        by_data[data] = entry
        observables.append(entry)

    for data, tags in _file_identity_pairs(alert):
        add(data, tags)
    return observables


def resolve_response_observables(alert, source_engine, hostname, host_ips, agent_id):
    """Response-action observables: ioc:false (no independent TI value) but
    the handle a responder needs to actually DO something -- isolate a
    host, kill a process, disable an account, block a port. Every entry
    carries an re&ct:<category> tag.

    Suricata's http/tls/dns/ja3 sub-fields and `dns.query_name` are
    deliberately never touched here -- confirmed unreachable-by-design
    (separate Elasticsearch documents per Suricata event_type, see
    so-alert-reference/ingest/suricata.common) or actively wrong
    (dns.query_name is a rule-text dissect bug, see
    so-alert-reference/ingest/suricata.alert), not just unbuilt."""
    observables = []
    if source_engine in ('suricata', 'sigma'):
        observables += _network_flow_response_observables(alert, source_engine)
    if source_engine == 'sigma':
        observables += _sigma_response_observables(alert, hostname, host_ips, agent_id)
    if source_engine == 'yara':
        observables += _yara_response_observables(alert)
    return observables


# ==================================================================
# SECTION 4 -- build the full TheHive alert body
# ==================================================================
def build_hive_alert(alert: dict) -> dict:
    """Entry point: raw SOC alert of any shape -> full TheHive 5 alert
    body, metadata AND observables."""
    if not isinstance(alert, dict):
        alert = {}
    alert = unwrap_webhook(alert)

    source_engine = detect_source_engine(alert)
    iocs = extract_iocs(alert, source_engine)
    hostname = iocs['hostname']['value'] if iocs['hostname']['found'] else None
    host_ips = iocs['host_ip'] or []
    agent_id = iocs['agent_id']['value'] if iocs['agent_id']['found'] else None
    sensor_name = iocs['sensor_name']

    rule_name = resolve_rule_name(alert)
    rule_uuid = resolve_rule_uuid(alert)
    severity = resolve_severity(alert, source_engine)
    timestamp_ms = resolve_timestamp_ms(alert)
    source_ref = resolve_source_ref(alert, hostname, rule_uuid, timestamp_ms)
    context_line = resolve_context_line(alert, source_engine)

    severity_label = {1: 'LOW', 2: 'MEDIUM', 3: 'HIGH', 4: 'CRITICAL'}[severity]

    # Suricata alerts have no single "host" (see extract_context) -- fall
    # back to the network flow for the title instead of a fabricated
    # "unknown-host". Sigma/YARA keep the original hostname behavior.
    if hostname:
        host_part = hostname
    elif source_engine == 'suricata':
        src, dst, _proto = resolve_network_flow(alert)
        host_part = f"{src} -> {dst}" if src and dst else (sensor_name or 'unknown-flow')
    else:
        host_part = 'unknown-host'

    title = f"[{severity_label}] {rule_name} - {host_part}"

    # network.community_id is the pivot key to this flow's companion
    # Elasticsearch documents (http/tls/dns event_type records SO indexes
    # SEPARATELY from the alert -- see resolve_response_observables'
    # docstring). This function can't join across documents, but exposing
    # the key lets an analyst manually find what it can't reach: the
    # actual domain/SNI/JA3 for an HTTP/TLS-based Suricata alert. Sysmon
    # network_connection events also compute a real community_id
    # (so-alert-reference/ingest/sysmon's trailing {"community_id": {}}
    # processor) -- nested under event_data.network.* for a Sigma alert,
    # not top-level like Suricata's, hence the fallback.
    community_id = first_non_empty(
        get_path(alert, 'network.community_id'),
        get_path(alert, 'event_data.network.community_id'),
    )

    description_lines = [
        f"Detection engine: {source_engine}",
        f"Rule: {rule_name}" + (f" ({rule_uuid})" if rule_uuid else ""),
    ]
    if hostname:
        description_lines.append(f"Host: {hostname}" + (f" ({host_ips[0]})" if host_ips else ""))
    if agent_id:
        description_lines.append(f"Agent ID: {agent_id}")
    if context_line:
        description_lines.append(context_line)
    if sensor_name:
        description_lines.append(f"Sensor: {sensor_name}")
    if community_id:
        description_lines.append(f"Flow ID (community_id): {community_id}")
    description = "\n".join(description_lines)

    return {
        "type": source_engine,
        "source": "security-onion",
        "sourceRef": source_ref,
        "title": title,
        "description": description,
        "severity": severity,
        "tlp": DEFAULT_TLP,
        "pap": DEFAULT_PAP,
        "date": timestamp_ms,
        "tags": build_tags(source_engine, rule_name, hostname, host_ips, agent_id, sensor_name, community_id),
        "observables": build_observables(iocs) + resolve_response_observables(
            alert, source_engine, hostname, host_ips, agent_id,
        ),
    }


# ==================================================================
# n8n entry point -- must be the LAST code in the box. n8n's NATIVE
# Python runner (v2.0+) exposes only `_items` (all-items mode) or
# `_item` (per-item mode) -- not `_input`, which was Pyodide-only and
# was removed in v2.0. `_items` is already a plain list shaped like
# [{"json": {...}}, ...]. Set the node's Mode to "Run Once for All Items".
# ==================================================================
results = []
for item in _items:
    try:
        raw = item.get("json") if isinstance(item, dict) else None
        results.append({"json": build_hive_alert(raw)})
    except Exception as e:
        results.append({"json": {
            "error": f"hive_alert_full failed: {e}",
            "raw_item": item.get("json") if isinstance(item, dict) else None,
        }})

return results