"""Stage 3 output contract (architecture §8, §18; v5 redesign, `newdesign.md`).

`ContextualAssessment` is what `nodes/context.py`'s single LLM call produces
(or, on any failure, what its deterministic fallback produces — the two paths
share this exact schema so nothing downstream can tell which one ran except
by reading `evidence_situation`).

`additional_investigation_gaps` is deliberately `list[str]`, not `list[Gap]`
like `RawEvidence.investigation_gaps` — architecture's own worked example
(§8) shows plain strings here, a narrower convention than Stage 1/2's
structured `Gap` model. Don't "fix" this to match the other one.

**v5 (`newdesign.md`) removed `ContextualModifier`/`contextual_modifiers`,
`confidence`, and `llm_criticality_score`** — all three only ever fed the
numeric priority-scoring formula (`scoring.py`), which v5 deletes entirely in
favor of an LLM-direct `priority_band` produced by Stage 4. `EvidenceSource`/
`EvidenceSituation` replace `confidence`: instead of a single vague label,
Stage 3 now reports per-source status (present/empty/missing) across the 8
Stage 1 evidence sources, an overall reliability judgment, and a concrete
analyst follow-up list — feeding Stage 4's priority rubric and safety
backstop directly, per `newdesign.md` §3.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class MitreMapping(BaseModel):
    technique_id: str
    technique_name: str = ""
    tactic: str = ""
    confidence: Literal["high", "medium", "low"]
    basis: str = ""


class CorrelationDecision(BaseModel):
    action: Literal["new", "merge"]
    merge_into_case_id: str | None = None
    kill_chain_progression_detected: bool = False
    reasoning: str = ""


class EvidenceSource(BaseModel):
    """One Stage 1 evidence source's status, per `newdesign.md` §3 TASK 5.
    `"present"`/`"empty"` vs `"missing"` is the load-bearing distinction:
    "checked and found nothing" (real, exculpatory-or-neutral signal) is
    never the same thing as "could not check" (a reliability gap) — see
    `EvidenceSituation`'s docstring."""

    source_name: str
    status: Literal["present", "empty", "missing"]
    impact_on_triage: str


class EvidenceSituation(BaseModel):
    """Replaces `confidence`/`contextual_modifiers`/`llm_criticality_score`
    (v5, `newdesign.md` §3/§4). `sources` covers exactly the 8 Stage 1
    evidence sources named in `newdesign.md` §3 TASK 5: `fp_signal`,
    `rule_context`, `open_cases`, `closed_cases_summary`, `asset_context`,
    `related_alerts_24h`, `process_history_24h`, `opencti_enrichment`
    (`cortex_results`, a property on `canonical_alert` rather than a Stage 1
    tool, is assessed too per the prompt's special-case instructions but has
    no dedicated `EvidenceSource` slot of its own the way the 8 named tools
    do).

    `overall_evidence_reliability` drives Stage 4's priority floor
    (`newdesign.md` §4: "low" forbids P4/P5, enforced first by prompt
    instruction and then by `nodes/analyze.py::_apply_safety_backstop` as a
    deterministic backstop). `analyst_must_verify` is Stage 3's own list of
    concrete manual-verification tasks — every item must reappear verbatim in
    `TriageVerdict.investigation_gaps` (`newdesign.md` §4)."""

    sources: list[EvidenceSource]
    overall_evidence_reliability: Literal["high", "medium", "low"]
    analyst_must_verify: list[str]


class ExtractedObservable(BaseModel):
    """One IOC the LLM identified from behavioral analysis or a Cortex
    malicious/suspicious verdict — never from `canonical_alert.observables`,
    which n8n already extracted (see schemas/alert.py::Observables). This is
    for things n8n's extractor doesn't see: a suspicious parent process, a
    file dropped to a suspicious path, a domain/IP/hash the LLM surfaces from
    command-line parsing or a Cortex hit that wasn't already an observable.

    `"process-path"` (renamed from the original bare `"process"`, 2026-08-21)
    — the `process` bucket's items are specifically an executable PATH worth
    actioning on (block/quarantine), not the process object as a whole; the
    more specific label says what a downstream consumer would actually do
    with the value."""

    observable_type: Literal["process-path", "file", "domain", "url", "ip", "hash"]
    value: str
    rationale: str
    confidence: Literal["high", "medium", "low"]
    source: Literal["behavioral_analysis", "cortex_result", "command_line_parsing"]


class ExtractedObservables(BaseModel):
    """Mirrors the type granularity of `schemas.alert.Observables`
    (external_ips/domains/urls split, not one combined "network" bucket) so
    the two shapes stay consistent for whatever downstream code consumes
    both. `process`/`file`/`hash` have no equivalent in `Observables` — those
    are exclusively LLM-derived, not something n8n's extractor produces."""

    process: list[ExtractedObservable] = Field(default_factory=list)
    file: list[ExtractedObservable] = Field(default_factory=list)
    external_ips: list[ExtractedObservable] = Field(default_factory=list)
    domains: list[ExtractedObservable] = Field(default_factory=list)
    urls: list[ExtractedObservable] = Field(default_factory=list)
    hash: list[ExtractedObservable] = Field(default_factory=list)


class ContextualAssessment(BaseModel):
    refined_mitre_mapping: list[MitreMapping] = Field(default_factory=list)
    correlation_decision: CorrelationDecision
    additional_investigation_gaps: list[str] = Field(default_factory=list)
    extracted_observables: ExtractedObservables = Field(default_factory=ExtractedObservables)
    evidence_situation: EvidenceSituation
    stage_3_duration_ms: int = 0
