"""Stage 0 boundary models: the raw n8n webhook payload and the CanonicalAlert
that every later stage reads.

Field coverage is derived from three sources of ground truth, never from guesses:

1. `sigma-alert-sample.json` — one REAL captured alert. Covers the
   `endpoint.events.process` dataset shape and only that one.
2. `ingest-templates.txt` — a live `logs-detections.alerts-so/_mapping` dump
   across 24 backing indices (2026.06.21 → 2026.07.16). 438 `event_data.*` leaf
   fields plus 29 top-level. Gives field *names and types*, never values.
3. `so-alert-reference/` — Security Onion's own ingest pipelines and ECS/SO
   component templates.

Architecture §18's model list (AlertWebhookPayload, CanonicalAlert, Observables,
Rule, Host, User, Process, Network, File) is illustrative of the core models, not
a ceiling. `CodeSignature`, `OSInfo`, `Library`, `MalwareVerdict`, and
`RelatedEntities` are additions covering real fields the live mapping proves
Security Onion can send. See CLAUDE.md "Deployment-specific decisions".

Every field except the small required core is Optional with a safe default, so
`alert_builder.py` can stay presence-guarded and degrade to None rather than
raise on any shape not yet confirmed against real data.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

# The four values alert_builder.PROFILE_BY_ENGINE can emit. nodes/gather.py and
# nodes/rag.py switch on these for deterministic tool/retrieval selection
# (architecture §6-§7, implementation guide §1.1).
InvestigationProfile = Literal[
    "network_threat",
    "endpoint_behavior",
    "malicious_file",
    "generic",
]


class HashBundle(BaseModel):
    """Hashes are lists, not scalars: one alert can legitimately carry several
    of the same algorithm (process hash + file hash + dll hash). Extractors
    append, so every field needs a per-instance default_factory."""

    md5: list[str] = Field(default_factory=list)
    sha1: list[str] = Field(default_factory=list)
    sha256: list[str] = Field(default_factory=list)
    sha512: list[str] = Field(default_factory=list)
    imphash: list[str] = Field(default_factory=list)
    # ssdeep — fuzzy/similarity hash. Strelka-only (gap #7, added 2026-08-19).
    # `file.hash.ssdeep`, tier 3 (so-analysis/elasticsearch templates). No
    # real Strelka alert exists in this deployment yet — see File's docstring.
    ssdeep: list[str] = Field(default_factory=list)

    def is_empty(self) -> bool:
        return not any(
            (self.md5, self.sha1, self.sha256, self.sha512, self.imphash, self.ssdeep)
        )


class Observables(BaseModel):
    """The IOC surface. Per implementation guide §0.2 this is sourced from
    `hive_alert.observables` (n8n extracted them and Cortex scored them before
    /triage was called) — NEVER by regexing raw_alert text fields."""

    external_ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    urls: list[str] = Field(default_factory=list)
    hashes: HashBundle = Field(default_factory=HashBundle)


class RelatedEntities(BaseModel):
    """ECS `related.*` — entity roll-ups Elastic Agent computes on the source
    event itself (`event_data.related.{ip,hash,user,hosts}`, confirmed in the
    live mapping).

    Deliberately NOT merged into `Observables`. Implementation guide §0.2 makes
    `hive_alert.observables` the single IOC source of truth, and merging these
    would duplicate upstream n8n extraction logic across two systems. They are
    carried as a separate, clearly-labelled field so the data is not silently
    dropped — a later stage may correlate against them, but they are not IOCs
    for triage purposes until that decision is made explicitly."""

    ip: list[str] = Field(default_factory=list)
    hash: list[str] = Field(default_factory=list)
    user: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)

    def is_empty(self) -> bool:
        return not any((self.ip, self.hash, self.user, self.hosts))


class CodeSignature(BaseModel):
    """Authenticode signing status. Present on three separate namespaces in the
    live mapping — `process.code_signature.*`, `dll.code_signature.*`,
    `file.code_signature.*` — plus an `Ext.code_signature` variant on each, so
    it gets one shared model rather than three copies of four fields.

    `trusted=False` on a binary in a system path is a meaningful likelihood
    signal; `trusted=True` with `subject_name="Microsoft Windows"` is a
    meaningful false-positive signal. Both matter to Stage 3."""

    trusted: bool | None = None
    subject_name: str | None = None
    status: str | None = None
    exists: bool | None = None

    def is_empty(self) -> bool:
        return all(
            v is None
            for v in (self.trusted, self.subject_name, self.status, self.exists)
        )


class OSInfo(BaseModel):
    """`event_data.host.os.*`. Typed rather than left as a raw dict so that
    Stage 3 sees a stable shape (architecture §12: no raw dicts across stage
    boundaries)."""

    name: str | None = None
    family: str | None = None
    full: str | None = None
    platform: str | None = None
    type: str | None = None
    version: str | None = None
    build: str | None = None
    kernel: str | None = None


class Rule(BaseModel):
    """The detection rule that fired.

    `uuid` is the join key for `detection_rule_lookup` against the so-detection
    index (`so_detection.publicId`) and for `get_fp_signal`. `native_severity`
    is the cross-engine-normalized `event.severity` integer; `level` is the
    engine's own textual level (`sigma_level` / `event.severity_label`), kept
    separately because the Sigma level string is
    what feeds `rule_severity_score` in architecture §10's formula."""

    name: str
    uuid: str = ""
    native_severity: int = 2
    level: str | None = None
    product: str | None = None
    category: str | None = None
    service: str | None = None


class Host(BaseModel):
    hostname: str
    ip: list[str] = Field(default_factory=list)
    mac: list[str] = Field(default_factory=list)
    os: OSInfo | None = None
    host_id: str | None = None
    architecture: str | None = None


class User(BaseModel):
    """`real_name`/`real_id` come from `event_data.user.Ext.real.*` — the
    account behind an impersonation, which differs from `name` when a process
    runs under an impersonated token."""

    name: str
    id: str | None = None
    domain: str | None = None
    real_name: str | None = None
    real_id: str | None = None


class ApiCall(BaseModel):
    """`event_data.process.Ext.api.*` — the `endpoint.events.api` dataset shape.
    Elastic Defend's API-call telemetry: which Windows API a process invoked,
    against what target, with which access rights.

    This is the primary process-injection evidence surface. `VirtualAllocEx` +
    `WriteProcessMemory` + `CreateRemoteThread` against another process, or an
    `OpenProcess` with `PROCESS_VM_WRITE`, is the difference between "a process
    ran" and "a process wrote into another process's memory". `behaviors` is
    Defend's own classification of the call.

    Types follow the live mapping exactly: `parameters.address` and
    `parameters.size` are `long` (not keyword), as is
    `parameters.desired_access_numeric`, while `desired_access` is the keyword
    form (e.g. "PROCESS_VM_WRITE|PROCESS_VM_OPERATION").

    SYNTHETIC COVERAGE ONLY — no real `endpoint.events.api` alert has been
    captured in this deployment yet."""

    name: str | None = None
    behaviors: list[str] = Field(default_factory=list)
    target_address_name: str | None = None
    address: int | None = None
    size: int | None = None
    desired_access: str | None = None
    desired_access_numeric: int | None = None
    handle_type: str | None = None

    def is_empty(self) -> bool:
        return all(
            v in (None, [])
            for v in (
                self.name,
                self.behaviors,
                self.target_address_name,
                self.address,
                self.size,
                self.desired_access,
                self.desired_access_numeric,
                self.handle_type,
            )
        )


class Process(BaseModel):
    """Process telemetry.

    `entity_id` / `parent_entity_id` / `ancestry` are Elastic Agent's process
    tree join keys. They let `elasticsearch_process_history` (architecture §6,
    tool 7) reconstruct the real parent chain instead of doing a blind 24h
    time-window scan on the host — the difference between "processes that ran
    nearby" and "this process's actual ancestors".

    `integrity_level` / `elevation_level` / `logon_type` are elevation and
    session context, direct inputs to impact reasoning in Stage 3.

    `description`/`product`/`company`/`file_version`/`architecture` (added
    2026-08-19, gap #5) are the executable's embedded PE version-resource
    metadata — the same "right-click -> Properties -> Details" fields, e.g.
    catching a renamed/masquerading binary whose company field says
    something other than the vendor it's pretending to be. TIER 1 — live-
    confirmed 2026-08-19 against a real captured PowerShell-engine alert on
    this deployment: `event_data.process.pe.{company,description,
    file_version,product}` all populated (`imphash`/`original_file_name`
    from the same `pe` object were already read below before this
    addition). `architecture` remains tier 3 only — not observed populated
    on the one real example checked."""

    pid: int | None = None
    name: str | None = None
    path: str | None = None
    command_line: str | None = None
    working_directory: str | None = None
    args: list[str] = Field(default_factory=list)

    entity_id: str | None = None
    ancestry: list[str] = Field(default_factory=list)

    parent_pid: int | None = None
    parent_name: str | None = None
    parent_path: str | None = None
    parent_command_line: str | None = None
    parent_entity_id: str | None = None

    integrity_level: str | None = None
    elevation_level: str | None = None
    logon_type: str | None = None
    authentication_package: str | None = None

    code_signature: CodeSignature | None = None
    parent_code_signature: CodeSignature | None = None
    original_file_name: str | None = None
    exit_code: int | None = None

    description: str | None = None
    product: str | None = None
    company: str | None = None
    file_version: str | None = None
    architecture: str | None = None

    # Populated only for the endpoint.events.api dataset shape. Pairs with
    # CanonicalAlert.target_process — the API call names what was done, the
    # target process names what it was done to.
    api: ApiCall | None = None


class Library(BaseModel):
    """A loaded module — `event_data.dll.*`, the `endpoint.events.library`
    dataset shape.

    Deliberately NOT folded into `File`: a DLL loaded into a running process is
    not the same thing as a file written to disk, and collapsing them would make
    the two indistinguishable to Stage 3. Unsigned or untrusted module loads
    into a signed process are a distinct detection concept.

    SYNTHETIC COVERAGE ONLY — field paths taken from the live mapping's
    `event_data.dll.*` union. No real `endpoint.events.library` alert exists in
    this deployment to validate against yet."""

    name: str | None = None
    path: str | None = None
    code_signature: CodeSignature | None = None
    original_file_name: str | None = None
    file_version: str | None = None
    size: int | None = None


class MalwareVerdict(BaseModel):
    """Elastic Defend's own malware assessment, carried on
    `event_data.file.Ext.malware_classification.*` and
    `.Ext.malware_signature.*`.

    This is a pre-computed local verdict sitting inside the alert — an
    independent likelihood signal alongside Cortex's threat intel. Modelled so
    it is not dropped; no scoring stage consumes it yet.

    SYNTHETIC COVERAGE ONLY — no real `endpoint.events.file` alert exists here
    to validate against."""

    classification_identifier: str | None = None
    classification_score: float | None = None
    classification_threshold: float | None = None
    signature_identifier: str | None = None
    signature_name: str | None = None
    matches: list[str] = Field(default_factory=list)


class File(BaseModel):
    """File context. Populated from two distinct, non-overlapping shapes:

    - `event_data.file.*` — the Sigma `endpoint.events.file` dataset
    - `raw_alert.file.*` + top-level `raw_alert.hash.*` — the YARA/Strelka shape
      (Security Onion's strelka.file ingest pipeline renames `scan.hash` to a
      top-level `hash`, sibling of `file`, NOT nested under it)

    Both are SYNTHETIC COVERAGE ONLY in this deployment — no file-extraction
    path or endpoint.events.file alert has been captured live.

    `entropy`/`pe_image_version`/`pe_flags`/`created`/`accessed`/`mtime`/
    `ctime`/`mode` (added 2026-08-19, gap #7) are Strelka-only —
    `raw_alert.scan.entropy.entropy` / `.scan.pe.image_version` /
    `.scan.pe.flags` / `.file.{created,accessed,mtime,ctime,mode}`. Tier 3
    (so-analysis/elasticsearch templates, `TEMPLATE-SCHEMA-REFERENCE.md`
    §5) — SYNTHETIC COVERAGE ONLY, same as the rest of this model; no real
    Strelka alert exists here because the Strelka sensor isn't enabled in
    this deployment (gap #13). No dedicated YARA match-score field exists in
    the resolved schema (`rule.score` doesn't exist) — `MalwareVerdict.matches`
    already covers the rule-name list, and the generic, non-YARA-specific
    `CanonicalAlert.risk_score` is the closest numeric signal available."""

    name: str | None = None
    path: str | None = None
    size: int | None = None
    mime_type: str | None = None
    extension: str | None = None
    directory: str | None = None
    owner: str | None = None
    code_signature: CodeSignature | None = None
    malware: MalwareVerdict | None = None
    quarantine_result: bool | None = None

    entropy: float | None = None
    pe_image_version: str | None = None
    pe_flags: str | None = None
    created: datetime | None = None
    accessed: datetime | None = None
    mtime: datetime | None = None
    ctime: datetime | None = None
    mode: str | None = None


class Registry(BaseModel):
    """Windows registry context — Sysmon event ID 13 confirmed (RegistryEvent:
    Value Set); EIDs 12/14 (object create/delete, key/value rename) share the
    same `event_data.registry.*` shape per the resolved template but have no
    real captured example yet. New model, added 2026-08-19 (gap #8a).

    TIER 1 as of the same day: `registry.hive`/`.key`/`.path`/`.value`/
    `.data.{type,strings}` confirmed on a REAL captured alert (
    tests/fixtures/sysmon-registry-alert-real.json, "Potential Persistence
    Via GlobalFlags", rule uuid 36803969-5421-41ec-b92f-8500f79c23b0) — not
    just tier 3 from `TEMPLATE-SCHEMA-REFERENCE.md` §4 as originally scoped.
    `.data.bytes` remains tier 3 only — this real fixture's registry value
    was a `strings`-typed DWORD, not a raw-binary one.

    `data` is modelled as a single flattened string, not the raw
    `.data.{type,strings,bytes}` triple — the type/bytes distinction is an
    Elastic Common Schema encoding detail (whether the registry value is a
    string, a multi-string array, or raw binary), not something Stage 3's
    behavioral reasoning needs split apart. The extractor prefers
    `data.strings` (joined) and falls back to `data.bytes` as a raw string.

    Dispatch (gap #10) turned out not to need a separate event-code lookup —
    `event_data.registry` is a distinctly-named key absent on every other
    Sysmon event shape, so its own presence is the dispatch signal, same
    pattern every other extractor in `alert_builder.py` already uses. See
    `_extract_registry_from_event_data`."""

    hive: str | None = None
    key: str | None = None
    path: str | None = None
    value: str | None = None
    data: str | None = None


class Network(BaseModel):
    """Network context.

    Suricata coverage is now REAL-FIXTURE VERIFIED (2026-08-18,
    `tests/fixtures/suricata-alert-real.json`) — `src_ip`/`dst_ip`/`src_port`/
    `dst_port`/`protocol` all confirmed populated on a real captured alert.
    The Sysmon network-connection path (via `_extract_network_from_event_data`)
    remains synthetic-only.

    `community_id` (added 2026-08-19, gap #5) is tier-1 verified on the same
    real Suricata fixture — `raw_alert["network"]["community_id"]`. It's the
    pivot key for correlating this alert against companion EVE-log documents
    (DNS/HTTP/TLS/flow) SO indexes as *separate* documents from the alert
    itself — see the planned `elasticsearch_suricata_flow_context` tool. Also
    populated by Sysmon network-connection events, nested at
    `event_data.network.community_id` rather than top-level."""

    src_ip: str | None = None
    dst_ip: str | None = None
    dst_ipv6: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    initiated: bool | None = None
    community_id: str | None = None


class CortexResult(BaseModel):
    """One analyzer's output for one observable, read from
    `hive_alert.observables[].reports`.

    This service never calls Cortex (architecture §6, §13) — the analyzers run
    before /triage is called and the reports arrive already attached.

    THIS MODEL CARRIES NO NUMBER. `CLAUDE.md`'s hard constraint is that
    `scoring.py` is the only place a number is computed, so no numeric score is
    derived here and none is stored. An earlier revision mapped taxonomy levels
    to 90/55/5 inside `alert_builder`; that pre-empted Stage 5 and was removed.

    `verdict` is a LIST, not a single label. An analyzer emits several taxonomy
    rows per observable and each carries its own level; collapsing them with a
    `max()` throws information away and forces an interpretation on Stage 5 that
    is Stage 5's to make. Only the adverse levels are kept — `malicious` and
    `suspicious`. `info` and `safe` are not verdicts and are not promoted into
    one; their absence from this list is what "nothing adverse" looks like.

    An empty `verdict` therefore means "no adverse taxonomy level was reported",
    NOT "clean" and NOT "unknown" — the distinction matters, and inventing a
    label for it here would be exactly the kind of premature judgement this
    model now avoids.

    `taxonomies` keeps every row verbatim — including `info`/`safe` rows and any
    detection ratios like `"0/91"` — so Stage 5 has the full evidence to score
    from without re-fetching or re-parsing `details`."""

    observable: str
    type: str = ""
    verdict: list[str] = Field(default_factory=list)
    details: str = ""
    analyzer: str = ""
    taxonomies: list[dict[str, Any]] = Field(default_factory=list)
    raw: dict[str, Any] = Field(default_factory=dict)


class CanonicalAlert(BaseModel):
    """The Stage 0 → Stage 1 contract. Every later stage reads this, never the
    raw payload.

    `timestamp` is the alert document's own `@timestamp`; `event_timestamp` is
    the underlying source event's `event_data.@timestamp`. These genuinely
    differ — by ~2 days in the one real captured sample — and architecture §10's
    `evidence_age_hours > 24` velocity branch does not say which it means. Both
    are carried so Stage 5 can make that choice explicitly rather than having it
    silently baked in here.

    `event_dataset` is the `event_data.event.dataset` discriminator
    (`endpoint.events.process`, `windows.sysmon_operational`, …). It records
    which shape this alert actually was, so a downstream gap can be attributed
    to the right extraction path."""

    alert_id: str
    timestamp: datetime
    event_timestamp: datetime | None = None
    source_engine: str = "unknown"
    investigation_profile: InvestigationProfile = "generic"
    event_dataset: str | None = None
    risk_score: float | None = None

    rule: Rule
    host: Host | None = None
    user: User | None = None
    network: Network | None = None
    process: Process | None = None
    target_process: Process | None = None
    library: Library | None = None
    file: File | None = None
    # Wired 2026-08-19 (gap #8a) — _extract_registry_from_event_data in
    # alert_builder.py, tier-1 verified. See Registry's docstring.
    registry: Registry | None = None

    observables: Observables = Field(default_factory=Observables)
    related_entities: RelatedEntities | None = None
    cortex_results: list[CortexResult] = Field(default_factory=list)

    asset_context: dict[str, Any] = Field(default_factory=dict)
    thehive_alert_id: str = ""
    thehive_observable_ids: dict[str, Any] = Field(default_factory=dict)


class AlertWebhookPayload(BaseModel):
    """What n8n POSTs to /triage (architecture §5).

    NOTE this is NOT the shape of `sigma-alert-sample.json`. That file is the
    n8n *webhook envelope* Security Onion sends INTO n8n —
    `[{headers, params, query, body, webhookUrl, executionMode}]`, where
    `[0]["body"]` is the raw alert. Unwrapping that envelope is n8n's job; by
    the time /triage is called, `raw_alert` is already the inner body."""

    thehive_alert_id: str
    raw_alert: dict[str, Any]
    asset_context: dict[str, Any] = Field(default_factory=dict)
