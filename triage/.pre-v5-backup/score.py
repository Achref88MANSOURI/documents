"""`priority_scoring` — Stage 5, SOC-3s Scoring System **v3**
(`newscoresystem.md`). Deterministic Python, <200ms budget, no I/O, no LLM.

"Never fails" is Stage 5's own documented failure mode (architecture §4's stage
table) — everything this node reads is already a validated Pydantic model by the
time it arrives, so there is nothing external to fail against. The try/except
below exists anyway, returning a safe neutral result on an unexpected internal
bug, because CLAUDE.md's "never fails the whole pipeline" expectation applies to
every node, not just the two LLM ones — a defensive backstop for a genuine code
defect, not a normal path.

Synchronous, not `async def` — every other `nodes/*.py` function is async
because it awaits real I/O. This one performs none; an `async def` with nothing
to await would be decoration, not a convention worth matching for its own sake.

Calls into `scoring.py` for the decision logic (architecture §18's file split:
`scoring.py` is pure functions, this file owns the typed
`TriageResult`/`PriorityScore` construction) — this is the one place those two
files meet.

**v3 note on the signature.** `verdict` is still the first parameter and is
still fully consumed — but only for `TriageResult`'s own fields.
`scoring.compute_priority` no longer takes it at all: v3's decision table never
reads Stage 4's judgment, so passing it into the scorer would imply an
influence that does not exist. Same for `context` — this node hands the whole
object to `compute_priority`, which reads exactly one thing from it
(`refined_mitre_mapping[].tactic`); `contextual_modifiers` and
`llm_criticality_score` are copied onto `TriageResult` for the analyst and are
read by no scoring rule.
"""

from __future__ import annotations

import logging
import time

import scoring
import scoring_config as cfg
from logging_config import alert_context
from schemas import (
    ContextualAssessment,
    EnrichedEvidence,
    PriorityScore,
    TriageResult,
    TriageVerdict,
)

logger = logging.getLogger(__name__)


def priority_scoring(
    verdict: TriageVerdict, context: ContextualAssessment, evidence: EnrichedEvidence
) -> TriageResult:
    alert_id = evidence.canonical_alert.alert_id
    with alert_context(alert_id):
        return _priority_scoring(verdict, context, evidence, alert_id)


def _priority_scoring(
    verdict: TriageVerdict, context: ContextualAssessment, evidence: EnrichedEvidence, alert_id: str
) -> TriageResult:
    started = time.monotonic()
    logger.info("Stage 5 started (deployment_mode=%s)", cfg.DEPLOYMENT_MODE)

    try:
        computed = scoring.compute_priority(context, evidence)
        priority = PriorityScore(**computed)
    except Exception as exc:  # noqa: BLE001 — see module docstring: a code-bug backstop
        logger.error("Stage 5 scoring failed unexpectedly for alert %s: %s", alert_id, exc)
        priority = _fallback_priority_score()

    result = TriageResult(
        alert_id=alert_id,
        verdict=verdict.verdict,
        recommended_action=verdict.recommended_action,
        summary=verdict.summary,
        reasoning=verdict.reasoning,
        likelihood=verdict.likelihood,
        impact_if_true=verdict.impact_if_true,
        evidence_citations=verdict.evidence_citations,
        actionable_observables=verdict.actionable_observables,
        stage_3_reasoning=context.correlation_decision.reasoning,
        contextual_modifiers=context.contextual_modifiers,
        refined_mitre_mapping=context.refined_mitre_mapping,
        investigation_gaps=context.additional_investigation_gaps,
        extracted_observables=context.extracted_observables,
        threat_intel=evidence.canonical_alert.cortex_results,
        runbook_matches=verdict.runbook_matches,
        gathered_evidence=evidence,
        stage_3_assessment=context,
        priority=priority,
        stage_5_duration_ms=int((time.monotonic() - started) * 1000),
    )
    logger.info(
        "Stage 5 completed in %dms: likelihood=%s impact=%s matrix=%s final=%s "
        "evidence_quality=%s override=%s mode=%s",
        result.stage_5_duration_ms,
        priority.likelihood_level,
        priority.impact_level,
        priority.matrix_priority,
        priority.final_priority,
        priority.evidence_quality,
        priority.evidence_quality_override_applied,
        priority.deployment_mode,
    )
    return result


def _fallback_priority_score() -> PriorityScore:
    """The neutral centre of both scales, which is P3 on the matrix — mid-queue,
    neither silently dropped nor falsely urgent.

    `evidence_quality` is reported as LOW and the override recorded as applied,
    because that is the truth of this situation: the scorer itself failed, so
    the evidence backing this result is maximally uncertain. The escalation is
    NOT actually applied to `final_priority` here — escalating a value that was
    never really computed would fabricate urgency out of a code bug. The
    explanation says so in words rather than leaving a reader to infer it.

    Reached only on an unexpected internal defect in `scoring.py`. Unlike Stage
    3/4's fallbacks this is not a documented failure mode with real-world
    triggers (a downed LLM), so it has no live-verification story of its own —
    there is nothing external to point it at.
    """
    return PriorityScore(
        likelihood_level=cfg.RULE_9_DEFAULT_LEVEL,
        likelihood_rule_fired=0,
        likelihood_rule_reason="Stage 5 scoring error — no rule was evaluated",
        likelihood_rule_status=cfg.STATUS_PROVISIONAL,
        impact_level=cfg.ASSET_IMPACT_DEFAULT,
        impact_governing_subscore="none",
        impact_modifiers_applied=[],
        impact_rule_status=cfg.STATUS_PROVISIONAL,
        matrix_priority="P3",
        matrix_status=cfg.MATRIX_STATUS,
        evidence_quality="LOW",
        evidence_quality_override_applied=False,
        final_priority="P3",
        deployment_mode=cfg.DEPLOYMENT_MODE,
        explanation=(
            "Stage 5 scoring error — neutral P3 fallback, not a real computation. "
            "No likelihood or impact rule was evaluated; the LOW evidence-quality "
            "escalation was deliberately NOT applied, as escalating an uncomputed "
            "value would fabricate urgency from a code defect."
        ),
    )
