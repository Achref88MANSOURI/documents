from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from schemas import (
    ApiCall,
    CanonicalAlert,
    CodeSignature,
    CortexResult,
    File,
    HashBundle,
    Host,
    Library,
    MalwareVerdict,
    Network,
    OSInfo,
    Observables,
    Process,
    RelatedEntities,
    Registry,
    Rule,
    User,
)

# A value starting with http(s):// is always a URL regardless of what n8n's
# Alert Builder node stamped as dataType (known mis-classification — see
# SOC-3s-ARCHITECTURE-v3-final.md §5).
URL_RE = re.compile(r"^https?://", re.IGNORECASE)

RULE_RE = re.compile(r"Rule:\s*(.+?)\s*\(([0-9a-fA-F-]{8,})\)")
HOST_RE = re.compile(r"Host:\s*(\S+)\s*\(([\d.]+)\)")
COMMAND_LINE_RE = re.compile(r"Command line:\s*(.+)", re.DOTALL)
ENGINE_TAG_RE = re.compile(r"^engine:(\w+)", re.IGNORECASE)

# Keyed on event.module. "strelka" is the module name Security Onion's
# file-extraction path writes; "yara" is kept alongside it because neither can
# be confirmed live — the alerts index has only ever carried event.module=sigma
# (verified 2026-08-08), so both file-engine spellings map to the same profile
# rather than guessing which one production will emit.
PROFILE_BY_ENGINE = {
    "suricata": "network_threat",
    "strelka": "malicious_file",
    "yara": "malicious_file",
    "sigma": "endpoint_behavior",
}

# The only taxonomy levels that constitute a verdict. `info` and `safe` never
# appear in CortexResult.verdict — their absence IS "nothing adverse reported".
# See schemas/alert.py's CortexResult docstring.
#
# No level->number map lives here (an earlier revision had one, mapping to
# 90/55/5/0 and storing it on CortexResult.score — CLAUDE.md's hard constraint
# is that scoring.py is the only place a number is computed, so that field and
# this mapping were removed). Similarly, there is deliberately no
# detection-ratio parsing here anymore: an earlier revision parsed "N/M" values
# and used N against threshold constants to independently DERIVE a verdict,
# overriding the analyzer's own `level`. That was retired 2026-08-13 — the
# analyzer's own `level` is taken as reported, verbatim, for every row. See the
# _summarize_taxonomies docstring for why this is not a re-run of the
# github.com regression it looks similar to.
_ADVERSE_LEVELS = ("malicious", "suspicious")

_HASH_FIELDS = {"md5", "sha1", "sha256", "sha512", "imphash"}


def _as_dict(value: Any) -> dict:
    """A field expected to be a nested object may collide with an unrelated
    top-level field of the same name that's actually a string (e.g. n8n's
    envelope has a top-level `source` string — the source *system* — which
    collides with Suricata's ECS `source` object, network source ip/port).
    Used everywhere a raw_alert/event_data sub-object is read, so a shape
    surprise degrades to "field absent" instead of an AttributeError."""
    return value if isinstance(value, dict) else {}


def _classify_observable_type(data_type: str, value: str) -> str:
    if URL_RE.match(value or ""):
        return "url"
    data_type = (data_type or "").lower()
    if data_type in ("ip", "ip-src", "ip-dst"):
        return "ip"
    if data_type == "fqdn":
        return "domain"
    return data_type


def _source_engine(raw_alert: dict) -> str:
    """`event.module` is the authoritative engine field. Confirmed two ways:

    1. `so-alert-reference/securityonion-es.py` — the real Security Onion Sigma
       alerter writes exactly `event.severity`, `event.module`, `event.dataset`
       and nothing else engine-identifying.
    2. Live aggregation over the whole alerts index (2026-08-08): 7719 docs,
       `event.module = "sigma"` / `event.dataset = "sigma.alert"` for 100% of
       them. No other value has ever been written — matching implementation
       guide §0.1, since only Sigma fires in this deployment.

    `event.dataset` is checked second, taking the segment before the first dot
    ("sigma.alert" -> "sigma"), for the case where module is absent but dataset
    is not. type/tags are legacy fallbacks for non-raw-SO-shaped callers (e.g. a
    TheHive-alert-shaped raw_alert), kept for defense, not expected to fire on
    real SO payloads.

    DO NOT reintroduce `ioc.source_engine` here. That field is not a Security
    Onion field — it came from a custom development-time ingest pipeline
    (`so-alert-reference/ingest/so-ioc-normalize`, whose own description says it
    runs *after* "Security Onion's own" chain) which set
    `ioc.source_engine = ctx.event.module`. It is derived FROM event.module, so
    it could never independently corroborate it, and it is mapped in only 1 of
    the 24 live backing indices. See CLAUDE.md."""
    engine = (_as_dict(raw_alert.get("event")).get("module") or "").lower()
    if engine:
        return engine
    dataset = (_as_dict(raw_alert.get("event")).get("dataset") or "").lower()
    if dataset:
        return dataset.split(".", 1)[0]
    engine = (raw_alert.get("type") or "").lower()
    if engine:
        return engine
    for tag in raw_alert.get("tags", []) or []:
        if not isinstance(tag, str):
            continue
        m = ENGINE_TAG_RE.match(tag)
        if m:
            return m.group(1).lower()
    return "unknown"


def _parse_rule(raw_alert: dict, description: str) -> Rule:
    """Structured path first: alerts carry a top-level `rule` dict —
    `rule.name`/`rule.uuid`, where Suricata's uuid is the SID as a string and
    YARA's uuid equals its rule name (Security Onion's own strelka.file ingest
    pipeline sets `rule.uuid = rule.name` — there's no separate YARA rule ID).

    CORRECTED 2026-08-08: an earlier version of this docstring claimed Sigma
    alerts do NOT carry this top-level dict and always fall through to
    description parsing. That is wrong. The real captured Sigma alert
    (sigma-alert-sample.json) carries top-level `rule.{name, uuid, product,
    category}`, and the live field mapping confirms `rule.{category, name,
    product, service, uuid}` at the top level of the alerts index. The
    structured path is the normal path for Sigma too. The description/tag
    regex fallbacks below are retained as genuine defense for non-raw-SO-shaped
    callers, not as the expected Sigma route.

    `level` is the engine's own textual severity — `sigma_level` on the alert
    doc, with `event.severity_label` as the equivalent confirmed in the same
    mapping. It is kept separate from the normalized
    integer `native_severity` because architecture §10's `rule_severity_score`
    is derived from the Sigma level string, not the integer.

    DO NOT read `event_data.rule.name` for rule identity (gap #11). A Sysmon
    event can carry its OWN internal `rule` object at that nested path — its
    RuleName config tag from sysmonconfig.xml, an author-chosen label
    unrelated to Sigma detection identity. Live-confirmed 2026-08-19 on a
    real captured alert (tests/fixtures/sysmon-registry-alert-real.json):
    `event_data.rule = {"name": "T1183,IFEO"}` while the REAL fired Sigma
    rule is the TOP-LEVEL `rule.name`, "Potential Persistence Via
    GlobalFlags" — completely different strings, same alert. `rule_data`
    below is read from `raw_alert.get("rule")` only, never `event_data`."""
    rule_data = _as_dict(raw_alert.get("rule"))
    name = rule_data.get("name") or ""
    uuid = rule_data.get("uuid") or ""

    if not name:
        m = RULE_RE.search(description)
        if m:
            name, uuid = m.group(1).strip(), m.group(2).strip()
    if not name:
        for tag in raw_alert.get("tags", []) or []:
            if tag.lower().startswith("rule:"):
                name = tag.split(":", 1)[1].strip()
                break
    if not name:
        name = raw_alert.get("title", "") or "unknown"

    level = raw_alert.get("sigma_level") or _as_dict(raw_alert.get("event")).get(
        "severity_label"
    )

    return Rule(
        name=name,
        uuid=str(uuid) if uuid else "",
        native_severity=_native_severity(raw_alert),
        level=level,
        product=rule_data.get("product"),
        category=rule_data.get("category"),
        service=rule_data.get("service"),
    )


def _native_severity(raw_alert: dict) -> int:
    """event.severity is the cross-engine-normalized field (confirmed via
    Security Onion's common/common.nids pipelines — Suricata's
    own rule.severity is pre-normalization and inverted, 1=highest, so it's
    deliberately NOT used here). Top-level severity is a defensive fallback for
    non-raw-SO-shaped callers only."""
    value = raw_alert.get("severity")
    if isinstance(value, int):
        return value
    event_severity = _as_dict(raw_alert.get("event")).get("severity")
    if isinstance(event_severity, int):
        return event_severity
    return 2


def _parse_host(raw_alert: dict, description: str) -> Host | None:
    m = HOST_RE.search(description)
    if m:
        return Host(hostname=m.group(1), ip=[m.group(2)])
    for tag in raw_alert.get("tags", []) or []:
        if re.match(r"^[a-zA-Z0-9-]+$", tag) and "-" in tag and "engine:" not in tag and "rule:" not in tag:
            # Bare hostname-shaped tag (e.g. "win-kvkmd51ggkq") — best-effort fallback.
            return Host(hostname=tag)
    return None


def _parse_process(description: str) -> Process | None:
    m = COMMAND_LINE_RE.search(description)
    if not m:
        return None
    return Process(command_line=m.group(1).strip())


def _as_list(value: Any) -> list:
    """ECS fields typed as arrays in the mapping are frequently emitted as a
    bare scalar when there's exactly one value (host.ip, related.ip, args...).
    Normalizes both shapes to a list so callers never branch on it."""
    if value is None:
        return []
    if isinstance(value, list):
        return [v for v in value if v is not None]
    return [value]


def _extract_code_signature(container: dict) -> CodeSignature | None:
    """Authenticode status, from either `<ns>.code_signature.*` or the
    `<ns>.Ext.code_signature.*` variant — both exist in the live mapping for
    process, dll and file namespaces. Ext is checked second and only fills
    fields the primary left unset.

    The mapping types process.Ext.code_signature as an object but the real
    captured alert emits `process.Ext.code_signature` as a LIST of objects
    while `process.code_signature` is a single object — so both shapes are
    handled. Returns None rather than an all-None model when nothing is
    present, so downstream `if process.code_signature` stays meaningful."""
    primary = _as_dict(container.get("code_signature"))
    ext_raw = _as_dict(container.get("Ext")).get("code_signature")
    if isinstance(ext_raw, list):
        ext = _as_dict(ext_raw[0]) if ext_raw else {}
    else:
        ext = _as_dict(ext_raw)

    merged = {**ext, **{k: v for k, v in primary.items() if v is not None}}
    if not merged:
        return None

    signature = CodeSignature(
        trusted=merged.get("trusted"),
        subject_name=merged.get("subject_name"),
        status=merged.get("status"),
        exists=merged.get("exists"),
    )
    return None if signature.is_empty() else signature


def _extract_os_info(host_data: dict) -> OSInfo | None:
    """event_data.host.os.* — confirmed fields: name, family, full, platform,
    type, version, build, kernel (Ext.variant exists too but has no typed home
    and is deliberately left unmapped)."""
    os_data = _as_dict(host_data.get("os"))
    if not os_data:
        return None
    return OSInfo(
        name=os_data.get("name"),
        family=os_data.get("family"),
        full=os_data.get("full"),
        platform=os_data.get("platform"),
        type=os_data.get("type"),
        version=os_data.get("version"),
        build=os_data.get("build"),
        kernel=os_data.get("kernel"),
    )


def _extract_host_from_event_data(event_data: dict) -> Host | None:
    """event_data.host.* — confirmed fields: hostname, name, id, ip, mac,
    architecture, os.*.

    `host.ip` is genuinely absent in the real captured endpoint.events.process
    alert even though the mapping types it — the agent's address is carried at
    `event_data.metadata.input.beats.host.ip` instead (Logstash beats-input
    metadata, confirmed in both the sample and the mapping). Used as a fallback
    so the host IP isn't lost for this shape."""
    host_data = _as_dict(event_data.get("host"))
    hostname = host_data.get("hostname") or host_data.get("name")
    if not hostname:
        return None

    ips = _as_list(host_data.get("ip"))
    if not ips:
        beats_host = _as_dict(
            _as_dict(_as_dict(_as_dict(event_data.get("metadata")).get("input")).get("beats")).get("host")
        )
        ips = _as_list(beats_host.get("ip"))

    return Host(
        hostname=hostname,
        ip=ips,
        mac=_as_list(host_data.get("mac")),
        os=_extract_os_info(host_data),
        host_id=host_data.get("id"),
        architecture=host_data.get("architecture"),
    )


def _extract_user_from_event_data(event_data: dict) -> User | None:
    """event_data.user.* — confirmed fields: name, id (a Windows SID), domain,
    Ext.real.{id,name}. `Ext.real.*` is the account behind an impersonated
    token and differs from `name` when impersonation is in play."""
    user_data = _as_dict(event_data.get("user"))
    name = user_data.get("name")
    if not name:
        return None
    user_id = user_data.get("id")
    real = _as_dict(_as_dict(user_data.get("Ext")).get("real"))
    real_id = real.get("id")
    return User(
        name=name,
        id=str(user_id) if user_id is not None else None,
        domain=user_data.get("domain"),
        real_name=real.get("name"),
        real_id=str(real_id) if real_id is not None else None,
    )


def _extract_process_from_event_data(event_data: dict) -> tuple[Process | None, HashBundle]:
    """event_data is the embedded source event a Sigma/ElastAlert2 alert matched
    against. Confirmed field paths, from live captured payloads across this
    project: event_data.process.{name,executable,command_line,pid,
    working_directory}, event_data.process.parent.{name,command_line,pid},
    event_data.process.hash.{sha256,md5}, event_data.process.pe.{imphash,
    original_file_name,company,description,file_version,product} (the last
    four added 2026-08-19, gap #5, live-confirmed on a real PowerShell-engine
    alert on this deployment), event_data.host.*, event_data.user.*. Every
    field is genuinely optional —
    which ones are populated depends on which Sigma rule fired and what
    telemetry it matched, not just which OS/agent produced it; nothing here
    assumes any single field is always present.

    Two extra fallback locations are also checked defensively and are NOT
    independently confirmed live: a top-level event_data.hash.* (in addition to
    the confirmed process.hash.*), and process.ppid (in addition to the
    confirmed process.parent.pid). Security Onion's own sysmon ingest pipeline
    (salt/elasticsearch/files/ingest/sysmon) names fields this way for at least
    one telemetry path — kept as harmless additional coverage, not a hard
    requirement, since every lookup here degrades to None rather than raising.
    """
    process_data = _as_dict(event_data.get("process"))
    hashes = HashBundle()
    if not process_data:
        return None, hashes

    parent = _as_dict(process_data.get("parent"))
    hash_data = _as_dict(process_data.get("hash")) or _as_dict(event_data.get("hash"))
    pe = _as_dict(process_data.get("pe"))

    for field in ("md5", "sha1", "sha256", "sha512"):
        value = hash_data.get(field)
        if value:
            getattr(hashes, field).append(value)
    imphash = pe.get("imphash") or hash_data.get("imphash")
    if imphash:
        hashes.imphash.append(imphash)

    command_line = process_data.get("command_line")
    name = process_data.get("name")
    path = process_data.get("executable")
    if not (command_line or name or path):
        return None, hashes

    parent_pid = parent.get("pid")
    if parent_pid is None:
        parent_pid = process_data.get("ppid")  # Sysmon convention, see docstring

    # Elastic Agent's process-tree join keys. entity_id identifies this exact
    # process instance, parent.entity_id its parent, and Ext.ancestry the full
    # ordered ancestor chain. elasticsearch_process_history (architecture §6,
    # tool 7) can walk these instead of blind-scanning a 24h window on the host.
    ext = _as_dict(process_data.get("Ext"))
    token = _as_dict(ext.get("token"))
    session_info = _as_dict(ext.get("session_info"))

    process = Process(
        pid=process_data.get("pid"),
        name=name,
        path=path,
        command_line=command_line,
        working_directory=process_data.get("working_directory"),
        args=_as_list(process_data.get("args")),
        entity_id=process_data.get("entity_id"),
        ancestry=_as_list(ext.get("ancestry")),
        parent_pid=parent_pid,
        parent_name=parent.get("name"),  # Elastic Defend only; None for Sysmon
        parent_path=parent.get("executable"),
        parent_command_line=parent.get("command_line"),
        parent_entity_id=parent.get("entity_id"),
        integrity_level=token.get("integrity_level_name"),
        elevation_level=token.get("elevation_level"),
        logon_type=session_info.get("logon_type"),
        authentication_package=session_info.get("authentication_package"),
        code_signature=_extract_code_signature(process_data),
        parent_code_signature=_extract_code_signature(parent),
        original_file_name=pe.get("original_file_name"),
        exit_code=process_data.get("exit_code"),
        api=_extract_api_call(ext),
        description=pe.get("description"),
        product=pe.get("product"),
        company=pe.get("company"),
        file_version=pe.get("file_version"),
        architecture=pe.get("architecture"),
    )
    return process, hashes


def _extract_api_call(process_ext: dict) -> ApiCall | None:
    """event_data.process.Ext.api.* — the endpoint.events.api dataset shape.
    Confirmed fields and types from the live mapping: api.name (keyword),
    api.behaviors (keyword, array), api.metadata.target_address_name (keyword),
    api.parameters.{address, size, desired_access_numeric} (long) and
    api.parameters.{desired_access, handle_type} (keyword).

    Pairs with _extract_target_process_from_event_data: the API call says what
    was done ("WriteProcessMemory", behaviors ["cross-process"]), the target
    process says what it was done to. Together they are the process-injection
    evidence surface.

    SYNTHETIC COVERAGE ONLY — no real endpoint.events.api alert has been
    captured in this deployment yet. Same presence-guarded, degrade-to-None
    discipline as every other extractor here."""
    api = _as_dict(process_ext.get("api"))
    if not api:
        return None

    parameters = _as_dict(api.get("parameters"))
    call = ApiCall(
        name=api.get("name"),
        behaviors=_as_list(api.get("behaviors")),
        target_address_name=_as_dict(api.get("metadata")).get("target_address_name"),
        address=parameters.get("address"),
        size=parameters.get("size"),
        desired_access=parameters.get("desired_access"),
        desired_access_numeric=parameters.get("desired_access_numeric"),
        handle_type=parameters.get("handle_type"),
    )
    return None if call.is_empty() else call


def _extract_target_process_from_event_data(event_data: dict) -> Process | None:
    """event_data.Target.process.* — a SECOND process carried by the alert: the
    target of a cross-process operation (Sysmon EID 10 process-access and
    related shapes). Confirmed fields in the live mapping: Target.process.
    {entity_id, executable, name, pid, Ext.token.integrity_level_name}.

    Modelled as its own CanonicalAlert.target_process rather than being merged
    into `process`, because "powershell.exe accessed lsass.exe" is two distinct
    processes and collapsing them would destroy the actual detection semantics.

    SYNTHETIC COVERAGE ONLY — no real alert carrying event_data.Target.* has
    been captured in this deployment yet.

    NOTE the capital T: `Target` is Elastic's own field name, not a typo."""
    target = _as_dict(event_data.get("Target"))
    process_data = _as_dict(target.get("process"))
    if not process_data:
        return None

    name = process_data.get("name")
    path = process_data.get("executable")
    pid = process_data.get("pid")
    if not (name or path or pid is not None):
        return None

    token = _as_dict(_as_dict(process_data.get("Ext")).get("token"))
    return Process(
        pid=pid,
        name=name,
        path=path,
        entity_id=process_data.get("entity_id"),
        integrity_level=token.get("integrity_level_name"),
        code_signature=_extract_code_signature(process_data),
    )


def _extract_dll_from_event_data(event_data: dict) -> tuple[Library | None, HashBundle]:
    """event_data.dll.* — the `endpoint.events.library` dataset shape (a module
    load). Confirmed fields in the live mapping: name, path, hash.sha256,
    pe.{imphash, file_version, original_file_name}, code_signature.*,
    Ext.code_signature.*, Ext.{size, load_index, relative_file_*_time}.

    Returned as a Library, not a File — see schemas/alert.py Library docstring
    for why a loaded module is not the same concept as a written file.
    dll hashes are merged into the shared observables HashBundle the same way
    process and file hashes already are.

    SYNTHETIC COVERAGE ONLY — no real endpoint.events.library alert exists in
    this deployment to validate against yet. Every lookup is presence-guarded
    and degrades to None, per the discipline the rest of this module follows."""
    dll_data = _as_dict(event_data.get("dll"))
    hashes = HashBundle()
    if not dll_data:
        return None, hashes

    hash_data = _as_dict(dll_data.get("hash"))
    pe = _as_dict(dll_data.get("pe"))
    for field in ("md5", "sha1", "sha256", "sha512"):
        value = hash_data.get(field)
        if value:
            getattr(hashes, field).append(value)
    imphash = pe.get("imphash") or hash_data.get("imphash")
    if imphash:
        hashes.imphash.append(imphash)

    name = dll_data.get("name")
    path = dll_data.get("path")
    if not (name or path or not hashes.is_empty()):
        return None, hashes

    ext = _as_dict(dll_data.get("Ext"))
    return Library(
        name=name,
        path=path,
        code_signature=_extract_code_signature(dll_data),
        original_file_name=pe.get("original_file_name"),
        file_version=pe.get("file_version"),
        size=ext.get("size"),
    ), hashes


def _extract_malware_verdict(file_ext: dict) -> MalwareVerdict | None:
    """event_data.file.Ext.malware_classification.* and .malware_signature.* —
    Elastic Defend's own local malware verdict, already computed and sitting
    inside the alert. An independent likelihood signal alongside Cortex's
    threat intel.

    SYNTHETIC COVERAGE ONLY. Modelled so the data isn't dropped; no scoring
    stage consumes it yet."""
    classification = _as_dict(file_ext.get("malware_classification"))
    signature = _as_dict(file_ext.get("malware_signature"))
    primary = _as_dict(signature.get("primary"))
    primary_sig = _as_dict(primary.get("signature"))

    verdict = MalwareVerdict(
        classification_identifier=classification.get("identifier"),
        classification_score=classification.get("score"),
        classification_threshold=classification.get("threshold"),
        signature_identifier=primary_sig.get("id") or signature.get("identifier"),
        signature_name=primary_sig.get("name"),
        matches=_as_list(primary.get("matches")),
    )
    if all(
        v in (None, [])
        for v in (
            verdict.classification_identifier,
            verdict.classification_score,
            verdict.classification_threshold,
            verdict.signature_identifier,
            verdict.signature_name,
            verdict.matches,
        )
    ):
        return None
    return verdict


def _extract_file_from_event_data(event_data: dict) -> tuple[File | None, HashBundle]:
    """event_data.file.* — the Sigma `endpoint.events.file` dataset shape.

    A DIFFERENT shape from _extract_file_from_raw_alert, which handles
    YARA/Strelka's top-level raw_alert.file.* + sibling raw_alert.hash.*. This
    one nests under event_data and keeps its hashes at file.hash.*, per the
    live mapping. Confirmed fields: name, path, size, extension, directory,
    owner, hash.sha256, code_signature.exists, created/mtime/accessed,
    drive_letter, pe.*, and the Ext.malware_* / Ext.quarantine_* namespaces.

    SYNTHETIC COVERAGE ONLY — no real endpoint.events.file alert exists in this
    deployment to validate against yet."""
    file_data = _as_dict(event_data.get("file"))
    hashes = HashBundle()
    if not file_data:
        return None, hashes

    hash_data = _as_dict(file_data.get("hash"))
    for field in ("md5", "sha1", "sha256", "sha512"):
        value = hash_data.get(field)
        if value:
            getattr(hashes, field).append(value)

    name = file_data.get("name")
    path = file_data.get("path")
    if not (name or path or not hashes.is_empty()):
        return None, hashes

    ext = _as_dict(file_data.get("Ext"))
    return File(
        name=name,
        path=path,
        size=file_data.get("size"),
        extension=file_data.get("extension"),
        directory=file_data.get("directory"),
        owner=file_data.get("owner"),
        code_signature=_extract_code_signature(file_data),
        malware=_extract_malware_verdict(ext),
        quarantine_result=ext.get("quarantine_result"),
    ), hashes


def _extract_related_entities(event_data: dict) -> RelatedEntities | None:
    """event_data.related.{ip,hash,user,hosts} — ECS entity roll-ups Elastic
    Agent computes on the source event.

    DELIBERATELY NOT merged into Observables. Implementation guide §0.2 makes
    hive_alert.observables the single IOC source of truth, and folding these in
    would duplicate n8n's upstream extraction across two systems — exactly the
    drift §0.2 warns against. Carried as a separate labelled field so real data
    isn't silently dropped, pending an explicit decision about whether triage
    should correlate on them."""
    related = _as_dict(event_data.get("related"))
    if not related:
        return None
    entities = RelatedEntities(
        ip=_as_list(related.get("ip")),
        hash=_as_list(related.get("hash")),
        user=_as_list(related.get("user")),
        hosts=_as_list(related.get("hosts")),
    )
    return None if entities.is_empty() else entities


def _extract_winlog_host(event_data: dict) -> Host | None:
    """Native Windows Event Log (winlog) channel — a distinct telemetry shape
    from the Elastic-Defend/Sysmon-via-elastic-agent one _extract_host_from_event_data
    handles. Confirmed field (live logs-detections.alerts-so field mapping,
    reference.txt): event_data.winlog.computer_name. Sigma rules matching
    native winlog channels (as opposed to Sysmon-derived process events) carry
    this instead of event_data.host.*."""
    winlog = _as_dict(event_data.get("winlog"))
    computer_name = winlog.get("computer_name")
    if not computer_name:
        return None
    return Host(hostname=computer_name)


def _extract_winlog_user(event_data: dict) -> User | None:
    """Confirmed fields: event_data.winlog.user.{name,identifier} (identifier
    is a Windows SID, mapped to User.id the same way _extract_user_from_event_data
    maps event_data.user.id)."""
    winlog = _as_dict(event_data.get("winlog"))
    user_data = _as_dict(winlog.get("user"))
    name = user_data.get("name")
    if not name:
        return None
    identifier = user_data.get("identifier")
    return User(name=name, id=str(identifier) if identifier is not None else None)


def _extract_winlog_process(event_data: dict) -> Process | None:
    """Confirmed field: event_data.winlog.process.pid only. The live field
    mapping this was verified against (reference.txt) does not show an
    Image/CommandLine/Name equivalent under this shape — event_data.winlog.
    event_data.{Company,Description,FileVersion,Product,...} look like
    PE-version-resource metadata (the same kind of fields Sysmon's own
    event_data.process.pe.* carries) but Process has no field for them and
    there isn't enough confirmed structure here to say which specific winlog
    event type produces this shape, so they're deliberately left unmapped
    rather than guessed at."""
    winlog = _as_dict(event_data.get("winlog"))
    process_data = _as_dict(winlog.get("process"))
    pid = process_data.get("pid")
    if pid is None:
        return None
    return Process(pid=pid)


def _extract_powershell_from_event_data(event_data: dict) -> Process | None:
    """PowerShell engine-lifecycle logging (Microsoft-Windows-PowerShell/
    Operational channel — a winlog sub-shape, but with its own dedicated
    event_data.powershell.* namespace). Confirmed fields: event_data.
    powershell.engine.{new_state,previous_state,version},
    event_data.powershell.process.executable_version,
    event_data.powershell.runspace_id. No pid/command_line/name exist for
    this shape — it's an engine state-change event, not a spawned process —
    synthesized into command_line the same way as SSH/HTTP below."""
    powershell = _as_dict(event_data.get("powershell"))
    engine = _as_dict(powershell.get("engine"))
    new_state = engine.get("new_state")
    previous_state = engine.get("previous_state")
    if not (new_state or previous_state):
        return None
    summary = f"powershell engine {previous_state or '?'} -> {new_state or '?'}"
    version = _as_dict(powershell.get("process")).get("executable_version")
    if version:
        summary += f" (v{version})"
    return Process(command_line=summary)


def _extract_ssh_auth_from_event_data(event_data: dict) -> Process | None:
    """SSH auth log lines (Filebeat system/auth module) carry no process
    telemetry at all — confirmed fields: event_data.system.auth.ssh.{event,
    method} (e.g. event="Accepted", method="publickey"). There is no typed
    CanonicalAlert field for an authentication outcome, so this is synthesized
    into command_line as a short textual description — the same "best
    available descriptive text, not necessarily a literal shell invocation"
    precedent _parse_process's description-regex fallback already uses."""
    ssh = _as_dict(_as_dict(_as_dict(event_data.get("system")).get("auth")).get("ssh"))
    event = ssh.get("event")
    if not event:
        return None
    method = ssh.get("method")
    summary = f"ssh {event}" + (f" ({method})" if method else "")
    return Process(command_line=summary)


def _extract_http_login_flow_from_event_data(event_data: dict) -> Process | None:
    """Kratos/identity-provider auth-flow logging (an HTTP-request-driven
    Sigma match, not host telemetry) — confirmed fields: event_data.http.
    {method,uri,useragent}, event_data.login_flow.{type,state}. Same
    synthesized-command_line approach as _extract_ssh_auth_from_event_data,
    for the same reason: no process exists here, but the request
    method/uri/login-flow state is the actual rule-relevant content."""
    http = _as_dict(event_data.get("http"))
    login_flow = _as_dict(event_data.get("login_flow"))
    method = http.get("method")
    uri = http.get("uri")
    if not (method or uri):
        return None
    summary = " ".join(p for p in (method, uri) if p)
    flow_type = login_flow.get("type")
    flow_state = login_flow.get("state")
    if flow_type or flow_state:
        summary += f" [login_flow type={flow_type or '?'} state={flow_state or '?'}]"
    return Process(command_line=summary)


def _extract_registry_from_event_data(event_data: dict) -> Registry | None:
    """event_data.registry.* — Sysmon EID 13 (RegistryEvent: Value Set),
    confirmed 2026-08-19 against a REAL captured alert
    (tests/fixtures/sysmon-registry-alert-real.json, "Potential Persistence
    Via GlobalFlags"): registry.{hive,key,path,value,data.{type,strings}}.

    Gap #10 resolved: no event-code/dataset dispatch is needed here, or
    anywhere else in this file — `event_data.event.dataset` is confirmed
    constant ("windows.sysmon_operational") across every Sysmon event type,
    so keying off it would never distinguish a registry event from a
    process-creation one. But this function follows the exact same
    presence-guarded pattern every other extractor in this file already
    uses (_extract_file_from_event_data, _extract_dll_from_event_data, …):
    `event_data.registry` is a distinctly-named key that simply doesn't
    exist on non-registry Sysmon events, so checking for its presence IS
    the dispatch — no separate event-code lookup required. Safe to call
    unconditionally alongside the other extractors.

    `data` flattens the raw `data.{type,strings,bytes}` triple into a
    single string — `strings` (joined) preferred, `bytes` as a defensive
    fallback for a binary-valued key this real fixture didn't exercise. See
    Registry's docstring in schemas/alert.py for why the split isn't kept."""
    registry_data = _as_dict(event_data.get("registry"))
    if not registry_data:
        return None
    data_obj = _as_dict(registry_data.get("data"))
    strings = _as_list(data_obj.get("strings"))
    data = ", ".join(str(s) for s in strings) if strings else data_obj.get("bytes")
    return Registry(
        hive=registry_data.get("hive"),
        key=registry_data.get("key"),
        path=registry_data.get("path"),
        value=registry_data.get("value"),
        data=data,
    )


def _split_host_port(value: str) -> tuple[str, int | None]:
    if value.count(":") == 1:
        host, _, port = value.partition(":")
        if port.isdigit():
            return host, int(port)
    return value, None


def _extract_network_from_event_data(event_data: dict) -> Network | None:
    """Network context nested under event_data rather than raw_alert's top
    level — used by _extract_network_from_raw_alert's callers as a fallback
    for the auth-log/HTTP shapes above, which carry a connecting source
    address but no Suricata-style top-level source/destination. Confirmed
    fields: event_data.source.{ip,address,port} (SSH auth logs) and
    event_data.http.request.remote (Kratos/HTTP request source — a
    "host[:port]" string per the field mapping, port split off defensively
    since the mapping only confirms it as an opaque keyword string).

    `event_data.network.community_id` (added 2026-08-19, gap #5) is a Sysmon
    network-connection convention, distinct from the SSH/HTTP source above —
    read defensively alongside whatever src_ip path fired; SYNTHETIC COVERAGE
    ONLY, no real Sysmon network_connection alert has been captured yet."""
    source = _as_dict(event_data.get("source"))
    src_ip = source.get("ip") or source.get("address")
    src_port = source.get("port")
    if not src_ip:
        http = _as_dict(event_data.get("http"))
        request = _as_dict(http.get("request"))
        remote = request.get("remote")
        if remote:
            src_ip, src_port = _split_host_port(remote)
    if not src_ip:
        return None
    community_id = _as_dict(event_data.get("network")).get("community_id")
    return Network(src_ip=src_ip, src_port=src_port, community_id=community_id)


def _merge_hashes(target: HashBundle, extra: HashBundle) -> None:
    for field in ("md5", "sha1", "sha256", "sha512", "imphash", "ssdeep"):
        existing = getattr(target, field)
        for value in getattr(extra, field):
            if value not in existing:
                existing.append(value)


def _extract_network_from_raw_alert(raw_alert: dict) -> Network | None:
    """Suricata alerts carry network context at the top level, not under
    event_data — confirmed: source.ip/destination.ip (some pipeline paths use
    src_ip/dest_ip instead, checked as a fallback), source.port/destination.port,
    network.transport. No process/user/hash fields exist for Suricata alerts at
    all — this is network context only.

    Note: n8n's Alert Builder envelope also has a top-level `source` key, but
    as a plain string (the source *system*, e.g. "security-onion") — not
    Suricata's ECS `source` object (network source ip/port). Guarded with an
    isinstance check so that envelope shape doesn't crash this extractor."""
    source = raw_alert.get("source")
    source = source if isinstance(source, dict) else {}
    destination = raw_alert.get("destination")
    destination = destination if isinstance(destination, dict) else {}
    network_meta = raw_alert.get("network")
    network_meta = network_meta if isinstance(network_meta, dict) else {}

    src_ip = source.get("ip") or raw_alert.get("src_ip")
    dst_ip = destination.get("ip") or raw_alert.get("dest_ip") or raw_alert.get("dst_ip")
    dst_ipv6 = destination.get("ipv6")
    if not (src_ip or dst_ip or dst_ipv6):
        return None

    return Network(
        src_ip=src_ip,
        dst_ip=dst_ip,
        dst_ipv6=dst_ipv6,
        src_port=source.get("port"),
        dst_port=destination.get("port"),
        protocol=network_meta.get("transport"),
        initiated=network_meta.get("initiated"),
        community_id=network_meta.get("community_id"),
    )


def _extract_file_from_raw_alert(raw_alert: dict) -> tuple[File | None, HashBundle]:
    """YARA/Strelka alerts carry file context at the top level, not under
    event_data — confirmed: file.name, file.path, file.mime_type (renamed from
    file.flavors.mime). Hashes are NOT nested under file.hash — Security Onion's
    own strelka.file ingest pipeline renames scan.hash to a top-level `hash`
    field, sibling of `file`, not nested under it (confirmed from so-ingest-
    reference). file.hash is checked too, defensively, in case a differently-
    shaped caller nests it there. No process/user/network fields are guaranteed
    for these alerts.

    entropy/pe_image_version/pe_flags/created/accessed/mtime/ctime/mode (added
    2026-08-19, gap #7) are also Strelka-only. entropy and the PE scan fields
    live under a separate top-level `scan.*` object, sibling of `file`, not
    nested under it — `scan.entropy.entropy`, `scan.pe.image_version`,
    `scan.pe.flags`. The timestamp/mode fields stay under `file.*` alongside
    name/path/size. `scan.pe.flags` is typed `text` in the resolved schema
    (singular value, not confirmed as an array) — joined defensively if a
    caller ever supplies a list, per `_as_list`'s established fallback
    pattern. `hash.ssdeep` sits alongside the other hash algorithms already
    read from `hash_data`. SYNTHETIC COVERAGE ONLY — see File's docstring."""
    file_data = _as_dict(raw_alert.get("file"))
    hashes = HashBundle()
    if not file_data:
        return None, hashes

    hash_data = _as_dict(raw_alert.get("hash")) or _as_dict(file_data.get("hash"))
    for field in ("md5", "sha1", "sha256", "sha512", "ssdeep"):
        value = hash_data.get(field)
        if value:
            getattr(hashes, field).append(value)

    name = file_data.get("name")
    path = file_data.get("path")
    if not (name or path or hash_data):
        return None, hashes

    scan = _as_dict(raw_alert.get("scan"))
    scan_pe = _as_dict(scan.get("pe"))
    entropy = _as_dict(scan.get("entropy")).get("entropy")
    pe_flags = scan_pe.get("flags")
    if isinstance(pe_flags, list):
        pe_flags = ", ".join(str(f) for f in pe_flags)

    return File(
        name=name,
        path=path,
        size=file_data.get("size"),
        mime_type=file_data.get("mime_type"),
        entropy=entropy,
        pe_image_version=scan_pe.get("image_version"),
        pe_flags=pe_flags,
        created=file_data.get("created"),
        accessed=file_data.get("accessed"),
        mtime=file_data.get("mtime"),
        ctime=file_data.get("ctime"),
        mode=file_data.get("mode"),
    ), hashes


def _parse_timestamp(raw_alert: dict) -> datetime:
    """@timestamp (ISO8601) is the real raw-SO-doc field — confirmed universal
    across the live logs-detections.alerts-so mapping and every ingest pipeline
    reviewed (all standardize on it as the ECS timestamp field). `date` (epoch-ms)
    is kept as a fallback for non-raw-SO-shaped callers only."""
    raw_ts = raw_alert.get("@timestamp")
    if isinstance(raw_ts, str):
        try:
            return datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        except ValueError:
            pass
    date_ms = raw_alert.get("date")
    if isinstance(date_ms, (int, float)):
        return datetime.fromtimestamp(date_ms / 1000, tz=timezone.utc)
    return datetime.now(timezone.utc)


def _parse_event_timestamp(event_data: dict) -> datetime | None:
    """event_data.@timestamp — when the UNDERLYING event happened, which is not
    when the alert fired. In the real captured sample these differ by ~2 days
    (alert 2026-07-22T08:55:59Z, event 2026-07-20T08:52:32Z).

    Architecture §10's velocity multiplier has an `evidence_age_hours > 24`
    branch but does not say which timestamp it means — against alert time that
    sample is fresh, against event time it is 48h stale and gets down-weighted.
    Both are carried on CanonicalAlert so Stage 5 makes that choice explicitly
    instead of having it silently baked in here. Returns None when absent
    rather than defaulting to now(), so "unknown" stays distinguishable from
    "just happened"."""
    raw_ts = event_data.get("@timestamp")
    if isinstance(raw_ts, str):
        try:
            return datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _build_observables(hive_alert: dict | None) -> Observables:
    """Raw SO alert docs never carry an `observables` list at all — that's purely
    a TheHive concept. The curated, IOC-flagged, Cortex-scored list only exists
    on hive_alert (n8n's Alert Builder created these observables and Cortex
    already scored them before /triage was ever called) — so this reads from
    hive_alert, not raw_alert. There is no supplementary raw_alert-derived
    IOC pass: `ioc.*` is not a Security Onion field (see _source_engine) and
    the guide §0.2 rule stands — IOCs come from TheHive, extracted upstream in
    n8n, and are never parsed out of raw_alert here."""
    external_ips: list[str] = []
    domains: list[str] = []
    urls: list[str] = []
    hashes = HashBundle()

    for obs in (hive_alert or {}).get("observables", []) or []:
        value = obs.get("data", "")
        if not value:
            continue
        obs_type = _classify_observable_type(obs.get("dataType", ""), value)

        if obs_type == "ip":
            external_ips.append(value)
        elif obs_type == "domain":
            domains.append(value)
        elif obs_type == "url":
            urls.append(value)
        elif obs_type == "hash":
            tag = next(
                (t.lower() for t in (obs.get("tags") or []) if t.lower() in _HASH_FIELDS),
                None,
            )
            if tag:
                getattr(hashes, tag).append(value)
            # Unrecognized hash tag: leave it out rather than guess the wrong
            # bucket — Agent 1 (perceive) fills this gap with LLM reasoning.

    return Observables(external_ips=external_ips, domains=domains, urls=urls, hashes=hashes)


def _merge_observables(target: Observables, extra: Observables) -> None:
    for field in ("external_ips", "domains", "urls"):
        existing = getattr(target, field)
        for value in getattr(extra, field):
            if value not in existing:
                existing.append(value)
    _merge_hashes(target.hashes, extra.hashes)


def _dedupe_taxonomies(taxonomies: list[dict]) -> list[dict]:
    """Analyzers routinely emit the same taxonomy row twice — the real payload
    for the xordump URL carries `VT:GetReport=3/97` and `VT:Scan=1/92` each
    exactly twice. Duplicates would double-weight a single datapoint."""
    seen: set[tuple] = set()
    unique: list[dict] = []
    for t in taxonomies or []:
        if not isinstance(t, dict):
            continue
        key = (t.get("namespace"), t.get("predicate"), t.get("value"), t.get("level"))
        if key not in seen:
            seen.add(key)
            unique.append(t)
    return unique


def _summarize_taxonomies(taxonomies: list[dict]) -> tuple[list[str], str]:
    """Structure an analyzer's taxonomy rows for Stage 3/5 — no scoring, no
    single-row election. Every row is kept verbatim in `details`; every
    adverse-labelled row (`malicious` or `suspicious`) contributes its level to
    the returned verdict list. `info`/`safe` rows are context only.

    THIS IS DELIBERATELY NOT "pick the one true verdict row". An earlier
    revision (2026-08-09) parsed detection-ratio values like "3/97" and used
    the count against thresholds to independently DERIVE a label, overriding
    whatever `level` the analyzer itself reported — because `max(level)` alone
    picked a context row and scored clean things as malicious (see below).
    That derivation step is exactly the kind of scoring judgement CLAUDE.md
    reserves for scoring.py / Stage 5, so it was retired 2026-08-13. The
    analyzer's own `level` is now taken as reported, full stop, for every row.

    REAL DATA THAT LOOKS LIKE A REGRESSION BUT ISN'T, from alert ~4636880
    (2026-08-13 capture): VirusTotal's github.com report carries TWO rows —

        {value: "56 resolution(s)", level: "malicious"}   <- context row
        {value: "0/91",             level: "info"}        <- the real verdict

    Under this function, `verdict` for that observable IS `["malicious"]` —
    genuinely, because a row genuinely says so. This differs from the
    2026-08-09 fix, which additionally computed a NUMBER (90) from that verdict
    and handed it to scoring as though it were authoritative, pinning
    threat_intel_adjustment near its maximum with no way for a human or an LLM
    to see it came from a resolution count, not a detection ratio. Here,
    nothing is computed — `verdict` is a label list, `details` shows every row
    with its own level attached (`"VT:GetReport=56 resolution(s) (malicious);
    VT:GetReport=0/91 (info)"`), so Stage 3/5's LLM reasoning — not
    alert_builder — is what weighs a context-row "malicious" against a
    genuinely clean detection ratio. That weighing is Stage 5's job per
    CLAUDE.md, not this function's.
    """
    taxonomies = _dedupe_taxonomies(taxonomies)
    if not taxonomies:
        return [], ""

    details = "; ".join(
        f"{t.get('namespace')}:{t.get('predicate')}={t.get('value')} ({t.get('level')})"
        for t in taxonomies
    )
    verdict = sorted({
        t.get("level") for t in taxonomies if t.get("level") in _ADVERSE_LEVELS
    })
    return verdict, details


def _build_cortex_results(hive_alert: dict | None) -> tuple[list[CortexResult], dict[str, Any]]:
    cortex_results: list[CortexResult] = []
    observable_ids: dict[str, Any] = {}

    for obs in (hive_alert or {}).get("observables", []) or []:
        obs_id = obs.get("_id", "")
        obs_data = obs.get("data", "")
        obs_type = obs.get("dataType", "")
        if obs_id and obs_data:
            observable_ids[obs_data] = obs_id

        for analyzer_name, report in (obs.get("reports") or {}).items():
            if not isinstance(report, dict):
                continue
            # TWO SHAPES, both real:
            #   TheHive's stock /api/v1/query observables projection -> report["taxonomies"]
            #   Cortex's own API / classic TheHive                   -> report["summary"]["taxonomies"]
            # Accepting both means the source can change without touching this.
            taxonomies = report.get("taxonomies")
            if taxonomies is None:
                taxonomies = _as_dict(report.get("summary")).get("taxonomies")
            if not taxonomies:
                continue
            verdict, details = _summarize_taxonomies(taxonomies)
            cortex_results.append(CortexResult(
                observable=obs_data,
                type=obs_type,
                verdict=verdict,
                details=details,
                analyzer=analyzer_name,
                raw=report,
            ))

    return cortex_results, observable_ids


def build_canonical_alert(
    raw_alert: dict,
    hive_alert: dict | None,
    asset_context: dict,
    thehive_alert_id: str = "",
) -> CanonicalAlert:
    """Deterministic, best-effort assembly of a CanonicalAlert from n8n's slim
    payload. This is NOT the LLM normalization step (that's Agent 1 / perceive,
    Phase 3) — it's the pre-LLM structural pass described in
    SOC-3s-ARCHITECTURE-v3-final.md §5.

    Per-engine structured extraction, all confirmed from live captured payloads
    and Security Onion's own ingest pipeline source (so-ingest-reference/):
    - Sigma: raw_alert["event_data"] carries the matched source event, in one
      of (at least) five confirmed shapes depending on which underlying log
      source the rule matched — checked in this order: Elastic-Defend/Sysmon
      process events (_extract_process_from_event_data /
      _extract_host_from_event_data / _extract_user_from_event_data), native
      Windows Event Log winlog events (_extract_winlog_*), PowerShell
      engine-lifecycle events (_extract_powershell_from_event_data), SSH auth
      log lines (_extract_ssh_auth_from_event_data), and Kratos/HTTP
      login-flow events (_extract_http_login_flow_from_event_data) — the
      latter three have no process telemetry at all, so their result is a
      short synthesized command_line description, not a literal shell
      invocation.
    - Suricata: no event_data; network context (source/destination ip/port,
      transport) lives at the top level of raw_alert — see
      _extract_network_from_raw_alert. No process/user/hash fields exist.
    - YARA/Strelka: no event_data; file context (name, path, hashes) lives at
      the top level of raw_alert — see _extract_file_from_raw_alert. No
      process/user/network fields are guaranteed.

    Additional event_data shapes, added 2026-08-08 from the live
    logs-detections.alerts-so field mapping (ingest-templates.txt), all
    SYNTHETIC-COVERAGE-ONLY — no real alert of these shapes has been captured
    in this deployment yet, so each follows the same presence-guarded,
    degrade-to-None discipline as the confirmed extractors above:
    - endpoint.events.file: event_data.file.* plus event_data.file.Ext.malware_*
      — _extract_file_from_event_data / _extract_malware_verdict
    - endpoint.events.library: event_data.dll.* — _extract_dll_from_event_data,
      returning a Library (not a File; see schemas/alert.py for why)
    - cross-process access (Sysmon EID 10 and kin): event_data.Target.process.*
      — _extract_target_process_from_event_data, a second distinct process
    - ECS entity roll-ups: event_data.related.* — _extract_related_entities,
      carried separately and NOT merged into observables (guide §0.2)
    Observables (IPs/domains/URLs/hashes) come from hive_alert, not raw_alert —
    raw SO alert docs never carry an observables list, only TheHive does (see
    _build_observables). Nothing supplements it from raw_alert: implementation
    guide §0.2 makes hive_alert.observables the single IOC source of truth, and
    `ioc.*` is not a Security Onion field.
    Every extractor degrades to None/empty on missing fields rather than
    raising — regexing the description string is the final fallback for
    rule/host identity when no structured field is present. Agent 1 fills any
    remaining gaps."""
    description = raw_alert.get("description", "") or ""
    source_engine = _source_engine(raw_alert)
    event_data = _as_dict(raw_alert.get("event_data"))

    cortex_results, observable_ids = _build_cortex_results(hive_alert)
    observables = _build_observables(hive_alert)

    host = (
        _extract_host_from_event_data(event_data)
        or _extract_winlog_host(event_data)
        or _parse_host(raw_alert, description)
    )
    user = _extract_user_from_event_data(event_data) or _extract_winlog_user(event_data)
    process, event_data_hashes = _extract_process_from_event_data(event_data)
    if process is None:
        process = _extract_winlog_process(event_data)
    if process is None:
        process = _extract_powershell_from_event_data(event_data)
    if process is None:
        process = _extract_ssh_auth_from_event_data(event_data)
    if process is None:
        process = _extract_http_login_flow_from_event_data(event_data)
    if process is None:
        process = _parse_process(description)
    network = _extract_network_from_raw_alert(raw_alert) or _extract_network_from_event_data(event_data)

    # Two non-overlapping file shapes: YARA/Strelka puts file context at the top
    # level of raw_alert, the endpoint.events.file Sigma dataset nests it under
    # event_data. Top level wins when both somehow appear.
    file_, file_hashes = _extract_file_from_raw_alert(raw_alert)
    if file_ is None:
        file_, file_hashes = _extract_file_from_event_data(event_data)

    library, dll_hashes = _extract_dll_from_event_data(event_data)
    registry = _extract_registry_from_event_data(event_data)

    _merge_hashes(observables.hashes, event_data_hashes)
    _merge_hashes(observables.hashes, file_hashes)
    _merge_hashes(observables.hashes, dll_hashes)

    inner_event = _as_dict(event_data.get("event"))
    # Sigma's matched event is nested (event_data.event.dataset); Suricata/YARA
    # have no event_data at all and carry the equivalent one level up, at
    # raw_alert.event.dataset (e.g. "suricata.alert") — the same top-level
    # object _source_engine() already reads for engine detection. Nested wins
    # when both somehow exist.
    top_level_event = _as_dict(raw_alert.get("event"))

    return CanonicalAlert(
        alert_id=(
            thehive_alert_id
            or raw_alert.get("sourceRef", "")
            or raw_alert.get("_id", "")
            or raw_alert.get("title", "unknown")
        ),
        timestamp=_parse_timestamp(raw_alert),
        event_timestamp=_parse_event_timestamp(event_data),
        source_engine=source_engine,
        investigation_profile=PROFILE_BY_ENGINE.get(source_engine, "generic"),
        event_dataset=inner_event.get("dataset") or top_level_event.get("dataset"),
        risk_score=inner_event.get("risk_score"),
        rule=_parse_rule(raw_alert, description),
        host=host,
        user=user,
        network=network,
        process=process,
        target_process=_extract_target_process_from_event_data(event_data),
        library=library,
        file=file_,
        registry=registry,
        observables=observables,
        related_entities=_extract_related_entities(event_data),
        cortex_results=cortex_results,
        asset_context=asset_context or {},
        thehive_alert_id=thehive_alert_id,
        thehive_observable_ids=observable_ids,
    )
