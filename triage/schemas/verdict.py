"""Stage 4 output contract (architecture §9, §18).

`TriageVerdict` is what `nodes/analyze.py`'s single LLM call produces (or, on
any failure, what its deterministic fallback produces — architecture §9's own
worked fallback literally sets `verdict="needs_review"`, proving that's a real
verdict value and not only a `recommended_action`).

Two fields diverge from architecture §9's literal worked example, both
resolved the same way CLAUDE.md's ground-truth hierarchy resolves every prior
case of the architecture doc being right on intent but wrong (or silent) on a
specific — see `RuleContext`'s four documented differences and the
`so-ioc-normalize` attribution for the established precedent this follows:

1. `impact_if_true` — the doc's worked example only ever shows the literal
   value `"severe"`; the full enum vocabulary is never given. `minor /
   moderate / significant / severe` is a deliberate choice here: ascending,
   4-tier, parallel in shape to `likelihood`'s doc-confirmed 4-tier scale,
   since both feed Stage 5's formula as parallel dimensions ("Those labels
   map to numeric ranges in Stage 5's formula" — architecture §9).
2. No `threat_intel[].score` anywhere downstream of this model — see
   `prompts/analyst_agent.py`'s `_summarize_evidence`. Architecture §9's
   worked `threat_intel` entry shape includes a `score` field; `CortexResult`
   (`schemas/alert.py`) carries no number by hard constraint (`scoring.py` is
   the only place a number is computed) — an earlier revision of
   `alert_builder.py` did exactly this and was reverted, see `CortexResult`'s
   own docstring. Not a `TriageVerdict` field itself, but the same resolution
   applies wherever this model's evidence summary is built.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from schemas.evidence import PlaybookMatch


class ActionableObservable(BaseModel):
    """Stage 4's judgment on ONE observable, drawn from the union of
    canonical_alert.observables (n8n's extraction), Stage 3's
    extracted_observables, and — on a merge — the target case's existing
    observables (`tools.thehive.fetch_case_observables_with_type`). Mirrors
    `schemas.assessment.ExtractedObservable`'s field shape for consistency,
    since this is the same kind of judgment one stage later: not "is this an
    IOC" (Stage 3's job) but "how seriously should this specific IOC be taken."

    2026-08-23 correction to the original 2026-08-23 build: this is now EVERY
    observable Stage 4 was shown, each annotated with a confidence — not a
    filtered "worth acting on" shortlist. Nothing gets silently dropped for
    being low-confidence; a weak signal still comes back with
    recommended_disposition="monitor" and confidence="low" rather than being
    omitted. See nodes/case_action.py's module docstring for why: this list is
    now the single source of truth for what gets written to TheHive, replacing
    the old path that wrote Stage 3's raw extraction directly and skipped
    Stage 4's judgment entirely.

    `confidence` is set by the LLM, for every item, required (not optional —
    unlike ExtractedObservable's `confidence`, this isn't a "usually present"
    field that a fallback might reasonably omit; Stage 4's whole job here is
    assigning it). `observable_id` is the opposite: NEVER set by the LLM
    (there is no such field in the schema sent to the model — see
    prompts/analyst_agent.py's _BASE_SCHEMA) — filled in post-hoc by
    nodes/case_action.py once the real TheHive write (or ID lookup for an
    already-existing observable) completes, same "set after the LLM call
    returns" pattern already used for stage_4_duration_ms/runbook_matches."""

    observable_type: Literal["process-path", "file", "domain", "url", "ip", "hash"]
    value: str
    recommended_disposition: Literal["block", "quarantine", "monitor"]
    confidence: Literal["high", "medium", "low"]
    reasoning: str
    observable_id: str | None = None


class TriageVerdict(BaseModel):
    likelihood: Literal["unlikely", "possible", "likely", "near_certain"]
    impact_if_true: Literal["minor", "moderate", "significant", "severe"]
    verdict: Literal["true_positive", "false_positive", "needs_review"]
    reasoning: str
    summary: str
    recommended_action: Literal[
        "create_case", "close_fp", "merge_quiet", "merge_and_retier", "needs_review"
    ]
    evidence_citations: list[str] = Field(default_factory=list)
    actionable_observables: list[ActionableObservable] = Field(default_factory=list)
    # Set post-hoc by nodes/analyze.py, same as stage_4_duration_ms below — the
    # LLM never sees or produces this field. tools.qdrant.retrieve_playbooks's
    # real hits against Stage 3's refined MITRE mapping, fetched before the LLM
    # call so they could be included in its prompt (2026-08-23, see CLAUDE.md).
    # Carried on TriageVerdict rather than added as a new priority_scoring
    # parameter since this is the object that already flows Stage 4 -> Stage 5.
    runbook_matches: list[PlaybookMatch] = Field(default_factory=list)
    stage_4_duration_ms: int = 0

    # v5 redesign (`newdesign.md` §4) — priority determination moves from a
    # deleted numeric scoring stage directly into this LLM call. priority_band
    # is assigned via the rubric in prompts/analyst_agent.py's SYSTEM_PROMPT,
    # from evidence fields directly (never from likelihood/impact_if_true —
    # no circular dependency). priority_reasoning states which rubric
    # condition fired and cites the evidence fields that drove it.
    # investigation_gaps consolidates Stage 3's evidence_situation.
    # analyst_must_verify (verbatim) plus any additional Stage 4 follow-ups —
    # this is the analyst task list, distinct from Stage 1's structured `Gap`
    # objects and from the old `additional_investigation_gaps` (removed with
    # the rest of ContextualAssessment's scoring-only fields).
    priority_band: Literal["P1", "P2", "P3", "P4", "P5"]
    priority_reasoning: str
    investigation_gaps: list[str] = Field(default_factory=list)
    # Set post-hoc by nodes/analyze.py::_apply_safety_backstop, same pattern
    # as runbook_matches/stage_4_duration_ms above — not LLM-facing (absent
    # from prompts/analyst_agent.py's _BASE_SCHEMA). newdesign.md §6 requires
    # TriageResult.safety_gate_applied but never says where that boolean is
    # supposed to originate; carrying it here, on the object that already
    # flows Stage 4 -> the new _build_triage_result, follows the exact
    # precedent those two fields already established rather than inventing a
    # new mechanism.
    safety_gate_applied: bool = False
