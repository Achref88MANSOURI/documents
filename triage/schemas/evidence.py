"""Stage 1 and Stage 2 boundary models (architecture §6, §7, §12).

`RawEvidence` is the Stage 1 output contract, `EnrichedEvidence` the Stage 2
one. Every evidence field is either populated or accompanied by a `Gap` that
says why — architecture §2 requirement 4: `{found: false}` must never mean two
different things.

`RuleContext` is modelled from the REAL so-detection document captured live on
2026-08-08 for rule 5e3cc4d8-3e68-43db-8656-eaaeefdec9cc, not from the
architecture doc's illustrative example. Three things differ from that example
and are called out on the fields themselves.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from schemas.alert import CanonicalAlert

# Sigma's placeholder values for "no false positives documented". A rule whose
# entire falsepositives list is placeholders has no real FP guidance, and
# feeding "Unknown" to Stage 3 as though it were an FP condition invites the
# model to reason about a false positive literally named "Unknown".
FALSEPOSITIVE_PLACEHOLDERS = {"unknown", "none", "unlikely", "n/a", "na", ""}


class Gap(BaseModel):
    """An explicit record of evidence that could not be gathered, and why.

    Architecture §6: every gap has a reason — `Gap(source="itop",
    reason="Connection timeout after 5s")`, never `reason="unknown"`.
    """

    source: str
    reason: str
    tool: str | None = None
    duration_ms: int | None = None


class LogSource(BaseModel):
    """Sigma `logsource:` block. Also available as doc-level `so_detection.
    {category, product, service}` on the so-detection document — the YAML is
    authoritative, the doc-level fields are the fallback."""

    category: str | None = None
    product: str | None = None
    service: str | None = None
    definition: str | None = None


class RuleContext(BaseModel):
    """`detection_rule_lookup` output — architecture §6 tool 2.

    THREE DIFFERENCES from the architecture doc's illustrative example, all
    confirmed against the real live document:

    1. `source_engine` comes from `so_detection.language` ("sigma"), NOT from
       `so_detection.engine` — which is the *execution* engine and reads
       "elastalert". Both are carried; picking the wrong one would silently
       poison the per-language parse branch for every rule.
    2. `mitre_attack` / `mitre_tactics` are NOT on the document. Doc-level
       `so_detection.tags` is null. They exist only inside the `content` field,
       which holds the original pre-compilation Sigma YAML, as a single
       `tags:` list mixing both (`attack.t1105`, `attack.command-and-control`).
       They are parsed out and normalised here — `attack.t1105` -> `T1105`.
    3. `falsepositives` is frequently the literal `["Unknown"]`, Sigma's
       placeholder for "none documented". `has_known_falsepositives` is the
       derived boolean Stage 3 reads; the raw list is kept for audit.
    """

    found: bool = False
    rule_uuid: str = ""

    # Identity
    title: str | None = None
    description: str | None = None
    author: str | None = None

    # Engine — see difference 1 above
    source_engine: str | None = None
    execution_engine: str | None = None

    # Severity. `severity` is the so-detection doc field, `level` the Sigma
    # YAML one. They agree on the captured rule (both "high") but are distinct
    # sources; architecture §10's rule_severity_score reads the Sigma level.
    severity: str | None = None
    level: str | None = None

    # Maturity: Sigma `status:` — stable/test/experimental/deprecated/unsupported.
    # An experimental rule firing is materially more likely to be a false
    # positive than a stable one. Not in the architecture doc's example; kept
    # because it is a real likelihood signal sitting in the data.
    #
    # This is a DAY-ONE false-positive signal: unlike get_fp_signal, which
    # starts empty and needs weeks of accumulated triage history before it says
    # anything, rule maturity is available on the very first alert.
    #
    # `has_reliable_status` follows the same derived-boolean pattern as
    # `has_known_falsepositives`: the raw string is kept for audit, the boolean
    # is what downstream reads. False covers both "explicitly below stable" and
    # "no status declared" — neither is evidence of a vetted rule.
    status: str | None = None
    has_reliable_status: bool = False

    # MITRE — see difference 2 above.
    # Sigma's `tags:` list is not purely techniques and tactics. It also carries
    # ATT&CK group ids (`attack.g0016`), software ids (`attack.s0002`), CVE refs
    # (`cve.2021-44228`) and CAR analytics (`car.2013-05-002`). Each gets its own
    # bucket rather than being force-fitted into mitre_tactics, which would
    # otherwise fill with things that are not tactics at all.
    mitre_attack: list[str] = Field(default_factory=list)
    mitre_tactics: list[str] = Field(default_factory=list)
    mitre_groups: list[str] = Field(default_factory=list)
    mitre_software: list[str] = Field(default_factory=list)
    other_tags: list[str] = Field(default_factory=list)

    # False positives — see difference 3 above
    falsepositives: list[str] = Field(default_factory=list)
    has_known_falsepositives: bool = False

    logsource: LogSource | None = None
    references: list[str] = Field(default_factory=list)

    # Operational state. A disabled rule that somehow produced an alert, or a
    # non-reporting one, is worth surfacing rather than silently ignoring.
    is_enabled: bool | None = None
    is_reporting: bool | None = None
    is_community: bool | None = None
    ruleset: str | None = None
    license: str | None = None

    source_created: datetime | None = None
    source_updated: datetime | None = None

    # Set when the `content` field was present but did not parse as YAML. The
    # doc-level fields still populate, so a parse failure degrades the MITRE
    # mapping without losing the rest of the rule metadata.
    content_parse_error: str | None = None


class FPSignal(BaseModel):
    """`get_fp_signal` output — architecture §6 tool 1.

    Two INDEPENDENT signals, not one joint rate: rule history regardless of
    host, host history regardless of rule — a deliberate deployment decision,
    see `tools/fp_tracking.py` module docstring. Diverges from architecture
    §6 tool 1's single joint-pair rate example (`WHERE rule_uuid=? AND
    host=?`).

    Counts, not rates: `record_triage_outcome` only ever writes a row when an
    alert closes as `false_positive` (never on a true-positive close), so
    `fp_count / total_count` has no valid denominator — architecture's own
    INSERT example only shows the FP-closure case, never a TP one, for the
    same reason. The count itself is the signal here, deliberately not
    normalized to 0.0-1.0."""

    rule_fp_count_24h: int = 0
    rule_fp_count_30d: int = 0
    host_fp_count_24h: int = 0
    host_fp_count_30d: int = 0


class OpenCTIRelation(BaseModel):
    """One STIX relationship from an OpenCTI indicator/observable to a related
    entity (malware, intrusion-set, threat-actor, campaign, ...). Graph
    context only — no score, no verdict label invented here. See CLAUDE.md:
    scoring.py is the only place a number is computed."""

    relationship_type: str
    related_entity_type: str | None = None
    related_entity_name: str | None = None


class OpenCTIEnrichment(BaseModel):
    """`opencti_observable_enrichment` output — a deployment-added Stage-1
    tool (`tools/opencti.py`), not in architecture v4's original 7. See
    CLAUDE.md "Deployment-specific decisions".

    Confirms whether an observable (IOC) from `hive_alert.observables` is a
    KNOWN indicator in OpenCTI's threat graph, and what it's related to.
    Distinct from the OpenCTI Cortex analyzer's taxonomy rows, which already
    arrive via `CortexResult` alongside VirusTotal's — this is a direct
    GraphQL query for graph relationships, not an analyzer verdict.

    `found=False` with no accompanying Gap is a real, meaningful answer — the
    observable was checked and OpenCTI has no record of it — not a failure to
    look. See architecture §2 requirement 4: `{found: false}` must never mean
    two different things."""

    observable: str
    found: bool = False
    entity_type: str | None = None
    indicator_names: list[str] = Field(default_factory=list)
    # OpenCTI's OWN x_opencti_score, passed through verbatim — not computed
    # here, so this does not violate the scoring.py constraint; it's foreign
    # data, same treatment as CortexResult.raw.
    opencti_score: int | None = None
    labels: list[str] = Field(default_factory=list)
    marking: list[str] = Field(default_factory=list)
    relations: list[OpenCTIRelation] = Field(default_factory=list)


class ShallowCase(BaseModel):
    """A TheHive case summary — deliberately shallow. Stage 3 judges merge/new
    from these; it never needs the full case body.

    VERIFIED AGAINST THE LIVE TheHive 5.6.1 SCHEMA 2026-08-08 via
    `/api/v1/describe/case`. `stage` and `status` are two DIFFERENT enumerations
    and conflating them is a real trap:

        stage  = New | InProgress | Closed              <- lifecycle position
        status = New | InProgress | TruePositive |
                 FalsePositive | Duplicated |
                 Indeterminate | Other                  <- resolution

    "Open" means `stage != "Closed"`, NOT `status != "Closed"` — there is no
    such status value. Filtering on the wrong one silently returns everything.

    `similar_observable_count` (added 2026-08-19, gap #12) is TheHive's own
    similarity-engine overlap score, populated only when this case was found
    via the native `getAlert -> similarCases` query stage
    (`tools/thehive.py::_fetch_similar_cases`). `None` when a result came
    from the older hand-rolled `listObservable -> case` fallback query —
    that's not a missing-data signal to flag specially, Stage 3 already
    treats an absent optional field as "no additional signal here".
    """

    case_id: str
    case_number: int | None = None
    title: str = ""
    severity: int | None = None
    stage: str | None = None
    status: str | None = None
    tags: list[str] = Field(default_factory=list)
    created_at: datetime | None = None
    observables: list[str] = Field(default_factory=list)
    similar_observable_count: int | None = None


# TheHive case `status` values that represent a resolved verdict, from the live
# schema. Anything outside these two is neither a TP nor an FP for scoring:
# Duplicated/Indeterminate/Other are genuine outcomes but carry no verdict
# signal, and New/InProgress mean the case was closed without a resolution set.
CASE_STATUS_TRUE_POSITIVE = "TruePositive"
CASE_STATUS_FALSE_POSITIVE = "FalsePositive"


class ClosedCasesSummary(BaseModel):
    """Counts, not a full list — architecture §9: Stage 4 sees historical
    context as counts only.

    `other_count` covers Duplicated / Indeterminate / Other and any case closed
    without a resolution. It is kept separate from tp/fp rather than folded into
    either, because a high "other" count means the historical signal is weak,
    which is different from it being negative.
    """

    tp_count: int = 0
    fp_count: int = 0
    other_count: int = 0
    avg_severity: float | None = None
    sample_case_ids: list[str] = Field(default_factory=list)
    # How the match was made. Rule uuid is NOT searchable in TheHive (no such
    # field on Case or Alert), so matching is by the `rule:<name>` tag and by
    # shared observables — see tools/thehive.py.
    matched_by: list[str] = Field(default_factory=list)


class AssetContext(BaseModel):
    """`itop_asset_lookup` output — architecture §6 tool 5.

    `criticality is None` with `found=True` is a real and important state: the
    asset exists in the CMDB but has no criticality assigned. Architecture §17
    calls unpopulated iTop the single biggest deployment risk, so that case must
    stay distinguishable from "asset not found at all".

    VERIFIED AGAINST LIVE iTOP 2026-08-08 (`PC::32`, win-kvkmd51ggkq) and
    RE-VERIFIED 2026-08-14 against a *different* iTop instance the deployment
    now points at (`http://172.20.24.220:8080`, stock community demo dataset —
    `Server1`-`4`, `VM1`-`4`, `Router1`/`Switch1`, no `PC` class; see
    `tools/itop.py` module docstring and `tests/fixtures/itop_demo_real.json`).
    Four fields the architecture doc lists / this tool exposes DO NOT EXIST or
    are unpopulated on the current instance:

    - `network_zone` — no such attribute on any class; the IP Management
      extension is not installed (`IPv4Subnet`/`IPv4Address` are not valid
      classes).
    - `data_sensitivity` — no such attribute on any class.
    - `owner` — no owner attribute; `contacts_list` is empty on every object
      sampled, so it cannot be resolved by any path.
    - `asset_number` — the attribute exists (it's on `PhysicalDevice`, same as
      the old instance) but is blank on every object checked. Hostname is
      therefore the only join key that actually works today, though the
      asset_number-primary lookup is kept — see `tools/itop.py`.

    These are a DATA-POPULATION task, not a code one (architecture §17, and the
    maintainer's explicit decision on 2026-08-08). They are kept in the model so
    that adding custom fields in iTop later is purely additive — one extra field
    read in `tools/itop.py`, same return model, no downstream change. Subnet
    maps must NOT be added to config or scoring to synthesise `network_zone`.

    `ip_addresses` is likewise always empty: no object in this iTop carries an
    IP (`PhysicalInterface` returns 0 rows, `managementip` is blank everywhere),
    so IP is not a usable lookup key.
    """

    found: bool = False
    hostname: str | None = None

    # iTop's attribute is `business_criticity` (its spelling). Observed enum
    # across all 32 live CIs: low / medium / high. The criticality -> numeric
    # score mapping belongs in scoring_config.py at build step 7, not here —
    # this tool returns the raw label.
    criticality: str | None = None

    owner: str | None = None
    organization: str | None = None
    services: list[str] = Field(default_factory=list)
    network_zone: str | None = None
    data_sensitivity: list[str] = Field(default_factory=list)
    asset_type: str | None = None
    ip_addresses: list[str] = Field(default_factory=list)

    # Identity and join keys.
    # `asset_number` holds the Elastic Agent host UUID and is tried FIRST as a
    # join key when populated: on the original (2026-08-08) deployment it
    # matched `event_data.host.id` exactly on a real alert
    # (c8fc26bf-dc76-4dba-adbb-bf31640d9c9f), strictly better than hostname,
    # which is case-sensitive in OQL `=` and breaks on FQDN vs short name. On
    # the current (2026-08-14) deployment's iTop it is blank on every object,
    # so hostname is the only join key that actually resolves anything today —
    # see the class docstring above and `tools/itop.py`.
    asset_number: str | None = None
    itop_class: str | None = None
    itop_id: str | None = None
    matched_by: str | None = None  # "asset_number" | "hostname"

    # Operational context that iTop does populate.
    status: str | None = None
    os_family: str | None = None
    os_version: str | None = None
    location: str | None = None
    obsolete: bool | None = None


class AlertSummary(BaseModel):
    """One related alert — architecture §6 tool 6. Capped at 50 by the caller."""

    timestamp: datetime | None = None
    rule_name: str = ""
    rule_uuid: str | None = None
    severity: int | None = None
    host: str | None = None
    user: str | None = None
    alert_id: str | None = None


class ProcessEvent(BaseModel):
    """One process event from host history — architecture §6 tool 7. Capped at
    50 by the caller."""

    timestamp: datetime | None = None
    name: str | None = None
    executable: str | None = None
    command_line: str | None = None
    pid: int | None = None
    parent_name: str | None = None
    parent_command_line: str | None = None
    entity_id: str | None = None
    user: str | None = None
    integrity_level: str | None = None
    elevation_level: str | None = None


class RawEvidence(BaseModel):
    """Stage 1 output — architecture §6.

    Optional fields mean "not gathered"; a corresponding entry in
    `investigation_gaps` says why. Empty lists are valid populated values and
    do NOT imply a gap.
    """

    canonical_alert: CanonicalAlert
    fp_signal: FPSignal | None = None
    rule_context: RuleContext | None = None
    open_cases: list[ShallowCase] = Field(default_factory=list)
    closed_cases_summary: ClosedCasesSummary = Field(default_factory=ClosedCasesSummary)
    asset_context: AssetContext | None = None
    related_alerts_24h: list[AlertSummary] = Field(default_factory=list)
    process_history_24h: list[ProcessEvent] = Field(default_factory=list)
    # A deployment-added Stage-1 tool (tools/opencti.py), not in architecture
    # v4's original 7 — see CLAUDE.md. Empty list is a real, checked-and-empty
    # result, same convention as the other Stage-1 outputs on this model.
    opencti_enrichment: list[OpenCTIEnrichment] = Field(default_factory=list)
    investigation_gaps: list[Gap] = Field(default_factory=list)
    stage_1_duration_ms: int = 0

    @property
    def cortex_results(self):
        """Architecture §6: Cortex reports are already on the CanonicalAlert,
        put there by alert_builder from hive_alert.observables[].reports. Stage
        1 never fetches them. Exposed here so Stage 2/3 read one object."""
        return self.canonical_alert.cortex_results


class MitreCandidate(BaseModel):
    """A `mitre_techniques` Qdrant hit — architecture §7 collection 1.

    VERIFIED AGAINST THE LIVE COLLECTION 2026-08-16 (697 points, 1024-dim
    Cosine, at `config.QDRANT_URL`). The real payload does NOT match
    architecture §7's illustrative example: no `description`,
    `detection_guidance`, `mitigations`, `example_procedures` or
    `priority_score_0_5` field exists on any ingested point, and `tactic` is a
    list, not a single string (a technique can belong to more than one
    tactic). Fields below are the real ones — see CLAUDE.md's ground-truth
    hierarchy; this is a third documented case of architecture's illustrative
    example diverging from the live shape, alongside RuleContext and
    so-ioc-normalize."""

    technique_id: str
    technique_name: str = ""  # payload key is `name` — mapped in tools/qdrant.py
    tactic: list[str] = Field(default_factory=list)
    platforms: list[str] = Field(default_factory=list)
    is_sub_technique: bool = False
    parent_technique_id: str | None = None
    x_mitre_version: str | None = None
    detection_strategy_id: str | None = None
    analytic_ids: list[str] = Field(default_factory=list)
    log_sources: list[str] = Field(default_factory=list)
    score: float = 0.0


class PlaybookMatch(BaseModel):
    """A `soc_playbooks` Qdrant hit — architecture §7 collection 2.

    VERIFIED AGAINST THE LIVE COLLECTION 2026-08-16 (48 points — 8 runbooks x
    ~6 sections each). Real source is the zhadyz/AI_SOC markdown runbooks,
    chunked by section — NOT architecture §7's structured
    `investigation_steps`/`verdict_indicators` object; no such fields exist on
    any real point. Multiple sections (Detection, Investigation Steps,
    Containment, ...) from the same runbook legitimately co-occurring in one
    result set is expected, not a duplicate — see tools/qdrant.py."""

    playbook_id: str  # payload key is `runbook_id` — mapped in tools/qdrant.py
    title: str = ""
    category: str = ""
    section: str = ""
    runbook_section_id: str = ""
    document_text: str = ""
    score: float = 0.0


class CveMatch(BaseModel):
    """A `cve_context` Qdrant hit — architecture §7 collection 3. Marked
    marginal value in §7; may remain stubbed to always return [].

    VERIFIED AGAINST THE LIVE COLLECTION 2026-08-16 (6,358 points, NVD API v2,
    CRITICAL severity, last 2 years). Real payload has `cvss_score`, not
    `cvss_v3_score`, plus `severity`/`published_date`; it has no
    `description`, `mitre_technique_ids`, `exploit_available` or `cisa_kev` —
    none of those architecture §7 fields are populated by this deployment's
    NVD ingest. `affected_products` is a CPE-style `vendor:product` keyword
    list — Qdrant's payload filter on it is EXACT match only, confirmed live
    (`match: {value: "openssl:openssl"}` -> 1 hit, `match: {value: "openssl"}`
    -> 0 hits), so a bare product name from evidence cannot be used as a
    server-side filter. See tools/qdrant.py's client-side substring fallback.
    """

    cve_id: str
    cvss_score: float | None = None
    severity: str | None = None
    published_date: str | None = None
    affected_products: list[str] = Field(default_factory=list)
    score: float = 0.0


class IncidentMatch(BaseModel):
    """An `incident_history` Qdrant hit — a deployment-added 4th RAG
    collection, not in architecture v4 §7's three. See CLAUDE.md
    "Deployment-specific decisions". A semantic-search complement to
    `tools.thehive.search_closed_cases_by_rule`'s exact rule_uuid match —
    intended to catch similar-but-not-identical incidents that exact matching
    can't, not to replace it.

    VERIFIED AGAINST THE LIVE COLLECTION 2026-08-16 (2 points today, sourced
    from TheHive closed cases, `stage == "Closed"` — the same underlying data
    `tools/thehive.py` already reads via the API). Grows as more cases close.
    """

    incident_id: str
    case_number: int | None = None
    title: str = ""
    severity: int | None = None
    status: str | None = None
    stage: str | None = None
    attack_type: str = ""
    tags: list[str] = Field(default_factory=list)
    summary: str = ""
    end_date: str | None = None
    engine: str | None = None
    score: float = 0.0


class EnrichedEvidence(RawEvidence):
    """Stage 2 output — RawEvidence plus RAG context (architecture §7, plus
    the deployment-added `incident_history` collection — see IncidentMatch).

    Subclasses RawEvidence rather than re-declaring its fields, so a field added
    to Stage 1 cannot go missing in Stage 2 — the v3 silent-evidence-loss bug
    §12 exists to prevent.

    No `playbook_matches` field here — playbook/runbook retrieval is out of
    Stage 2's scope (deliberately deferred; its natural query input is Stage
    3's confirmed MITRE mapping, not anything Stage 2 has). `PlaybookMatch`
    itself is still defined above and still produced by
    `tools.qdrant.retrieve_playbooks`, just not consumed by this model.
    """

    mitre_candidates: list[MitreCandidate] = Field(default_factory=list)
    cve_matches: list[CveMatch] = Field(default_factory=list)
    incident_matches: list[IncidentMatch] = Field(default_factory=list)
    stage_2_duration_ms: int = 0


def has_reliable_status(status: str | None) -> bool:
    """True only for a Sigma rule explicitly marked `stable`.

    Sigma's status vocabulary is stable / test / experimental / deprecated /
    unsupported. Only `stable` means the rule has been vetted in production.
    A missing status is treated as not-reliable: absence of a maturity claim is
    not a maturity claim.

    Note this is deliberately stricter than `rule_status_penalty` in
    scoring_config.py, which scores an absent status as 0 (no penalty — we
    cannot prove a rule is bad just because its author omitted a field) while
    this boolean reports it as not-confirmed-reliable. The two answer different
    questions: "should we deduct points" versus "is this rule vetted".
    """
    return isinstance(status, str) and status.strip().lower() == "stable"


def has_known_falsepositives(entries: list[str] | None) -> bool:
    """True when the list contains at least one entry that is not a Sigma
    placeholder. See RuleContext difference 3."""
    for entry in entries or []:
        if isinstance(entry, str) and entry.strip().lower() not in FALSEPOSITIVE_PLACEHOLDERS:
            return True
    return False
