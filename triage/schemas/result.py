"""Top-level triage result contract — v5 redesign (`newdesign.md`).

**v5 deletes the numeric/matrix scoring stage entirely** — `scoring.py`,
`scoring_config.py`, `nodes/score.py`, and this module's former `PriorityScore`
class (SOC-3s Scoring System v3, `newscoresystem.md`) are all gone. Priority
determination moves directly into Stage 4's LLM output as `TriageVerdict.
priority_band` (P1-P5), assigned via the rubric in
`prompts/analyst_agent.py`, with `priority_reasoning` as its one-sentence,
evidence-citing justification — no score, no matrix cell, no formula.
`nodes/analyze.py::_apply_safety_backstop` is the one deterministic
computation left anywhere near priority: escalating one band when Stage 3's
`evidence_situation.overall_evidence_reliability` is `"low"` and the LLM
assigned P4/P5 anyway.

`TriageResult` is the top-level result for one alert: `TriageVerdict`'s
judgment fields (including `priority_band`/`priority_reasoning`/
`investigation_gaps`/`safety_gate_applied`), `ContextualAssessment`'s
`evidence_situation`, plus the complete Stage 1/2/3 output for audit
drill-down. Built by a new thin, math-free function (`newdesign.md` §5) —
`main.py`'s pipeline no longer has a distinct Stage 5 node.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from schemas.alert import CortexResult
from schemas.assessment import ContextualAssessment, EvidenceSituation, ExtractedObservables, MitreMapping
from schemas.case_action import CaseActionResult
from schemas.evidence import EnrichedEvidence, PlaybookMatch
from schemas.verdict import ActionableObservable


class TriageResult(BaseModel):
    """The top-level result of one alert's triage — what `main.py`'s
    `/triage` endpoint actually returns to n8n (architecture §3), wrapped in
    `TriageResponse` below."""

    alert_id: str
    verdict: str
    recommended_action: str
    summary: str
    reasoning: str
    # likelihood/impact_if_true/evidence_citations/actionable_observables
    # (2026-08-23) surface the rest of TriageVerdict's detail — previously
    # only verdict/recommended_action/summary/reasoning were flattened here,
    # so n8n never saw the rest without a second lookup. The builder that
    # assembles TriageResult already receives the full TriageVerdict as its
    # first argument, so it copies these across too at construction time —
    # same place the original four fields were already being flattened from.
    likelihood: str = ""
    impact_if_true: str = ""
    evidence_citations: list[str] = Field(default_factory=list)
    actionable_observables: list[ActionableObservable] = Field(default_factory=list)
    # stage_3_reasoning/refined_mitre_mapping/investigation_gaps/
    # extracted_observables/threat_intel/runbook_matches (2026-08-23) surface
    # Stage 3's own reasoning and the real, untruncated evidence Stage 4 only
    # ever saw a firewalled summary of — n8n previously had no way to see any
    # of this without a second TheHive/ES lookup. extracted_observables here
    # is Stage 3's raw, already-hallucination-filtered extraction (distinct
    # from actionable_observables, Stage 4's per-item judgment) — always
    # present when non-empty; threat_intel alongside it is what lets a reader
    # judge which extractions are corroborated.
    #
    # investigation_gaps (v5, `newdesign.md` §9) now sources from
    # TriageVerdict.investigation_gaps — Stage 4's consolidated analyst task
    # list (Stage 3's evidence_situation.analyst_must_verify, verbatim, plus
    # Stage 4's own follow-ups) — not from the removed
    # ContextualAssessment.additional_investigation_gaps.
    #
    # contextual_modifiers is gone (v5 deleted ContextualModifier along with
    # the scoring formula it only ever fed).
    stage_3_reasoning: str = ""
    refined_mitre_mapping: list[MitreMapping] = Field(default_factory=list)
    investigation_gaps: list[str] = Field(default_factory=list)
    extracted_observables: ExtractedObservables = Field(default_factory=ExtractedObservables)
    threat_intel: list[CortexResult] = Field(default_factory=list)
    runbook_matches: list[PlaybookMatch] = Field(default_factory=list)
    # gathered_evidence/stage_3_assessment (2026-08-23) are the COMPLETE
    # Stage 1+2 and Stage 3 outputs, not cherry-picked fields — user-directed:
    # "put everything we collected and analyzed... so the analyst can see
    # what the llm is handling and what evidence we gathered." Deliberately
    # redundant with several fields above (e.g. extracted_observables /
    # threat_intel / stage_3_reasoning are already reachable through these
    # two objects) — the flat fields stay for quick-glance access without
    # walking the nested structure, these two are the full audit trail
    # underneath them.
    gathered_evidence: EnrichedEvidence | None = None
    stage_3_assessment: ContextualAssessment | None = None
    # v5 redesign (`newdesign.md` §6) — replaces the deleted PriorityScore.
    # priority_band/priority_reasoning/investigation_gaps (above) come
    # straight from TriageVerdict; evidence_situation is Stage 3's own
    # per-source reliability report, passed through for the same audit-trail
    # reason gathered_evidence/stage_3_assessment are. safety_gate_applied
    # reflects whether nodes/analyze.py::_apply_safety_backstop escalated the
    # LLM's own band assignment.
    priority_band: str = ""
    priority_reasoning: str = ""
    safety_gate_applied: bool = False
    evidence_situation: EvidenceSituation | None = None
    stage_5_duration_ms: int = 0
    # Set by nodes/case_action.py — see that node's module docstring for why
    # it's a separate node. None until the caller runs case_action and
    # assigns it; not a required constructor field, so a caller that never
    # runs case_action is unaffected.
    case_action: CaseActionResult | None = None


class TriageResponse(BaseModel):
    """`main.py`'s actual `/triage` HTTP response body. `success=False` with
    a partial `result` (or `None`) and `error`/`failed_stage` set is a valid
    HTTP 200 — this repo's chosen failure posture (CLAUDE.md, main.py build
    writeup): n8n's workflow never gets an HTTP error from this endpoint,
    only a structured indication that something didn't complete."""

    success: bool
    result: TriageResult | None = None
    error: str | None = None
    failed_stage: str | None = None
