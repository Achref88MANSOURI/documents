"""`analyst_verdict` — Stage 4, architecture §9. Second and LAST of exactly 2
LLM calls in the whole pipeline (CLAUDE.md hard constraint). Single-shot, no
tools: builds a sanitized prompt from `ContextualAssessment` + `EnrichedEvidence`
(never the raw evidence Stage 3 sees — see `prompts/analyst_agent.py`'s
firewall), calls the LLM once, parses/validates its response, and never raises
to its caller — any failure produces the same kind of deterministic
`TriageVerdict` fallback instead.

Not built on `nodes/_guard.py`, for the identical reason `nodes/context.py`
isn't: exactly one call, `httpx`'s own `timeout=` on the request is the only
layer needed, `_guarded`'s two-layer parallel-tool pattern doesn't apply to a
single sequential call.

`_extract_first_json_object` is duplicated here rather than imported from
`nodes.context` — the two are otherwise-independent stage modules in the
architecture's file map, and a 2-line defensive parse isn't worth a shared
cross-node dependency. Same live-observed failure mode it guards against:
under `json_object` mode `foundation-sec-reasoning:latest` was seen emitting
one valid JSON object then continuing with hallucinated extra turns;
`json_schema` mode didn't reproduce it in Stage 3's testing, but nothing
guarantees a different prompt shape can't trigger it here too.

`config.STAGE_4_LLM_TIMEOUT` needs the same generous headroom
`STAGE_3_LLM_TIMEOUT` already has in this deployment's `.env` — Stage 3's real
calls on this CPU-bound host took 271.1s and 323.2s (see `tests/test_context.py`
and `REPO-STATUS.md`); the 180s config default would very plausibly fire
mid-call. This is a config value only, same as Stage 3 — no line here branches
on CPU vs GPU.

**2026-08-23 addition — actionable-observables judgment (TASK 5).** On a
merge (`context.correlation_decision.action == "merge"`), this node now makes
one non-LLM call before building the prompt:
`tools.thehive.fetch_case_observables_with_type(merge_into_case_id)` — the
merge target's case_id is already resolved in Stage 3's output, available
before this node runs (`case_action.py`'s own dispatch confirms Stage 6
never resolves it, only consumes it). Not wrapped in `_guarded` for the same
reason the LLM call itself isn't — the function already self-times-out
(`config.STAGE_4_TOOL_TIMEOUT_THEHIVE`) and never raises. On `"new"` or a
failed fetch: `case_observables = []`, proceed — `TriageVerdict` has no
gap-list field to record a degraded fetch in, same limitation
`_validate_recommended_action` already works within.

**2026-08-23 addition — runbook retrieval.** Also before building the prompt:
`tools.qdrant.retrieve_playbooks`, queried from Stage 3's *refined* MITRE
mapping (`_build_playbook_query`, mirroring `nodes/rag.py::_build_mitre_query`'s
construction style) — `retrieve_playbooks` already existed, fully built and
live-verified against the real `soc_playbooks` Qdrant collection, just never
called anywhere (`nodes/rag.py`'s own docstring: its natural query input is
Stage 3's *refined* mapping, which Stage 2 doesn't have — Stage 3 is now
built, so that's resolved here instead of in Stage 2). Same unwrapped-call
reasoning as the TheHive fetch above: `retrieve_playbooks` is already NEVER
RAISES. Results are set onto `verdict.runbook_matches` post-hoc (same place
`stage_4_duration_ms` is already set post-hoc) rather than threaded as a new
`priority_scoring` parameter, since `TriageVerdict` is already the object
that flows from this stage into Stage 5.

**2026-08-23 fix — `_capped_max_tokens`.** Same fix as `nodes/context.py`'s
identical function (see that module's docstring for the live-caught bug) —
Stage 4's prompt is normally much smaller than Stage 3's, but nothing
structurally prevents a large `case_observables`/`runbook_matches` set from
growing it enough to matter, so the same defensive cap applies here too.
"""

from __future__ import annotations

import json
import logging
import time

import httpx

import config
import prompts.analyst_agent as prompts
from logging_config import alert_context
from schemas import ContextualAssessment, EnrichedEvidence, PlaybookMatch, TriageVerdict
from tools import qdrant, thehive

logger = logging.getLogger(__name__)


async def analyst_verdict(
    context: ContextualAssessment, evidence: EnrichedEvidence
) -> TriageVerdict:
    with alert_context(evidence.canonical_alert.alert_id):
        return await _analyst_verdict(context, evidence)


async def _analyst_verdict(
    context: ContextualAssessment, evidence: EnrichedEvidence
) -> TriageVerdict:
    started = time.monotonic()
    logger.info("Stage 4 started")

    case_observables: list[dict] = []
    merge_id = context.correlation_decision.merge_into_case_id
    if context.correlation_decision.action == "merge" and merge_id:
        case_observables, gap = await thehive.fetch_case_observables_with_type(merge_id)
        if gap:
            logger.warning(
                "Stage 4 could not fetch case %s's existing observables: %s",
                merge_id,
                gap.reason,
            )

    runbook_matches, playbook_gap = await qdrant.retrieve_playbooks(
        _build_playbook_query(context, evidence), timeout=config.STAGE_4_TOOL_TIMEOUT_QDRANT
    )
    if playbook_gap:
        logger.warning("Stage 4 could not retrieve playbooks: %s", playbook_gap.reason)

    try:
        raw_content = await _call_llm(context, evidence, case_observables, runbook_matches)
        parsed = _extract_first_json_object(raw_content)
        verdict = TriageVerdict.model_validate(parsed)
        verdict = _validate_recommended_action(verdict, context)
        verdict = _validate_actionable_observables(verdict, context, evidence, case_observables)
        verdict, gate_fired = _apply_safety_backstop(verdict, context)
        verdict.safety_gate_applied = gate_fired
    except Exception as exc:  # noqa: BLE001 — see module docstring, every failure falls back
        logger.warning("Stage 4 LLM call/parse failed, using deterministic fallback: %s", exc)
        verdict = _stage_4_fallback(context, evidence)

    verdict.runbook_matches = runbook_matches
    verdict.stage_4_duration_ms = int((time.monotonic() - started) * 1000)
    logger.info(
        "Stage 4 completed in %dms: verdict=%s recommended_action=%s priority_band=%s "
        "safety_gate_applied=%s",
        verdict.stage_4_duration_ms,
        verdict.verdict,
        verdict.recommended_action,
        verdict.priority_band,
        verdict.safety_gate_applied,
    )
    return verdict


def _capped_max_tokens(system_prompt: str, user_prompt: str, desired: int) -> int:
    """Caps the requested completion max_tokens so prompt + completion stays
    under the model's real context window — see config.py's
    LLM_MAX_CONTEXT_TOKENS/LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN/
    LLM_CONTEXT_SAFETY_MARGIN_TOKENS docstrings for the live-caught bug this
    closes and why the estimate is character-based and deliberately
    conservative. Duplicated in nodes/context.py rather than shared — same
    reasoning as _extract_first_json_object below: two otherwise-independent
    stage modules, not worth a cross-node dependency for a few lines."""
    estimated_prompt_tokens = len(system_prompt + user_prompt) / config.LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN
    available = (
        config.LLM_MAX_CONTEXT_TOKENS - estimated_prompt_tokens - config.LLM_CONTEXT_SAFETY_MARGIN_TOKENS
    )
    return max(config.LLM_MIN_COMPLETION_TOKENS, min(desired, int(available)))


async def _call_llm(
    context: ContextualAssessment,
    evidence: EnrichedEvidence,
    case_observables: list[dict],
    runbook_matches: list[PlaybookMatch],
) -> str:
    user_prompt = prompts.build_user_prompt(context, evidence, case_observables, runbook_matches)
    max_tokens = _capped_max_tokens(prompts.SYSTEM_PROMPT, user_prompt, config.STAGE_4_DESIRED_MAX_TOKENS)
    payload = {
        "model": config.LLM_ANALYZE_MODEL,
        "messages": [
            {"role": "system", "content": prompts.SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "TriageVerdict",
                "schema": prompts.build_triage_verdict_schema(context, evidence),
            },
        },
        "temperature": 0.1,
        "max_tokens": max_tokens,
        "stream": False,
    }
    logger.info(
        "Stage 4 LLM call started (model=%s, timeout=%ss, max_tokens=%d)",
        config.LLM_ANALYZE_MODEL,
        config.STAGE_4_LLM_TIMEOUT,
        max_tokens,
    )
    llm_started = time.monotonic()
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{config.LLM_ANALYZE_BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {config.LLM_ANALYZE_API_KEY}"},
            json=payload,
            timeout=config.STAGE_4_LLM_TIMEOUT,
        )
        resp.raise_for_status()
        logger.info("Stage 4 LLM call completed in %.1fs", time.monotonic() - llm_started)
        return resp.json()["choices"][0]["message"]["content"]


def _build_playbook_query(context: ContextualAssessment, evidence: EnrichedEvidence) -> str:
    """Mirrors nodes/rag.py::_build_mitre_query's construction style, but
    from Stage 3's REFINED mapping rather than Stage 1's raw rule lookup —
    that's the whole reason this retrieval lives here and not in Stage 2
    (see module docstring). Rule title plus each refined technique's
    id/name/tactic. An alert with no refined MITRE mapping at all produces a
    query built from the rule title alone; tools.qdrant.retrieve_playbooks
    already Gaps gracefully on a weak/empty query, so no separate gate is
    needed here."""
    parts = [evidence.canonical_alert.rule.name]
    for mapping in context.refined_mitre_mapping:
        parts.append(f"{mapping.technique_id} {mapping.technique_name} {mapping.tactic}".strip())
    return " — ".join(p.strip() for p in parts if p and p.strip())


def _extract_first_json_object(content: str) -> dict:
    """Only the first JSON value in the string is trustworthy — see module
    docstring and `nodes/context.py`'s identical function."""
    return json.JSONDecoder().raw_decode(content.strip())[0]


def _validate_recommended_action(
    verdict: TriageVerdict, context: ContextualAssessment
) -> TriageVerdict:
    """Defense-in-depth behind the schema-level enum constraint in
    prompts.analyst_agent.build_triage_verdict_schema — belt and suspenders
    for the case Ollama's schema enforcement doesn't hold, mirroring
    nodes/context.py::_validate_merge_target's exact role for Stage 3's
    analogous merge-target constraint.

    Unlike Stage 3's validator, this has no gap-list field to append a note
    to — TriageVerdict carries no `additional_investigation_gaps` equivalent
    per architecture §9's worked schema. Log-only is a deliberate, minor
    deviation from the Stage 3 pattern, not an oversight."""
    action = context.correlation_decision.action
    invalid = (action == "merge" and verdict.recommended_action == "create_case") or (
        action == "new" and verdict.recommended_action in ("merge_quiet", "merge_and_retier")
    )
    if invalid:
        logger.warning(
            "Stage 4 recommended_action=%r incompatible with correlation_decision.action=%r, "
            "falling back to needs_review",
            verdict.recommended_action,
            action,
        )
        verdict.recommended_action = "needs_review"
    return verdict


def _validate_actionable_observables(
    verdict: TriageVerdict,
    context: ContextualAssessment,
    evidence: EnrichedEvidence,
    case_observables: list[dict],
) -> TriageVerdict:
    """Same defense-in-depth role as nodes.context._validate_extracted_
    observables (see that function and CLAUDE.md's 2026-08-23 escaping-bug
    writeup), scoped to what Stage 4 actually saw — known_observables +
    extracted_observables + case_observables, the exact three sources
    TASK 5 names in prompts.analyst_agent.SYSTEM_PROMPT — not the full
    evidence Stage 4 never receives (that's Stage 3's firewall boundary,
    unchanged).

    Uses the identical fix: json.dumps(value, ensure_ascii=False)[1:-1]
    against a haystack built with the same ensure_ascii=False, so a value
    containing a backslash, quote, or non-ASCII character isn't wrongly
    discarded the same way the original bug discarded a real Windows path.

    Like _validate_recommended_action, TriageVerdict has no gap-list field —
    log-only."""
    known = evidence.canonical_alert.observables.model_dump()
    extracted = context.extracted_observables.model_dump()
    traceable_json = json.dumps(
        {
            "known_observables": known,
            "extracted_observables": extracted,
            "case_observables": case_observables,
        },
        default=str,
        ensure_ascii=False,
    )

    kept = []
    for item in verdict.actionable_observables:
        needle = json.dumps(item.value, ensure_ascii=False)[1:-1]
        if needle not in traceable_json:
            logger.warning(
                "Stage 4 actionable_observables value %r not traceable to known/"
                "extracted/case observables, discarding as a likely hallucination",
                item.value,
            )
            continue
        kept.append(item)
    verdict.actionable_observables = kept
    return verdict


def _apply_safety_backstop(
    verdict: TriageVerdict,
    context: ContextualAssessment,
) -> tuple[TriageVerdict, bool]:
    """Deterministic safety gate applied after Stage 4 LLM output is parsed
    (v5 redesign, `newdesign.md` §4).

    If evidence reliability is low AND the LLM assigned P4 or P5, escalate
    by one band. This catches cases where the LLM ignored the evidence
    situation instructions in the prompt.

    Returns the (possibly modified) verdict and a boolean indicating
    whether the gate fired."""
    if context.evidence_situation.overall_evidence_reliability != "low":
        return verdict, False

    escalation_map = {"P5": "P4", "P4": "P3"}
    if verdict.priority_band not in escalation_map:
        return verdict, False

    new_band = escalation_map[verdict.priority_band]
    new_reasoning = (
        verdict.priority_reasoning
        + f"\n\n[SAFETY GATE APPLIED]: Priority escalated from "
        f"{verdict.priority_band} to {new_band}. Evidence reliability was "
        f"'low' — automated triage cannot safely close or defer this alert. "
        f"A human analyst must review."
    )

    updated = verdict.model_copy(update={
        "priority_band": new_band,
        "priority_reasoning": new_reasoning,
    })
    return updated, True


def _stage_4_fallback(
    context: ContextualAssessment, evidence: EnrichedEvidence
) -> TriageVerdict:
    """architecture §9's original worked stage_4_fallback, extended per v5
    (`newdesign.md` §4) with `priority_band`/`priority_reasoning`/
    `investigation_gaps`. `context`/`evidence` are accepted to match that
    documented signature but unused in the body — unlike Stage 3's fallback,
    which does derive fields from its input, the doc's own Stage 4 fallback
    derives nothing from either argument. Never fabricates a verdict; always
    escalates to human review on failure.

    priority_band defaults to P2, not P3: when Stage 4 fails, the pipeline
    has no verdict at all. A failed pipeline cannot safely produce a
    low-priority result — P2 guarantees the alert reaches an analyst this
    shift (`newdesign.md` §4's own stated rationale for this choice)."""
    return TriageVerdict(
        likelihood="possible",
        impact_if_true="moderate",
        verdict="needs_review",
        reasoning="Stage 4 LLM unavailable, defaulting to human review",
        summary="Automated triage failed, analyst review required",
        recommended_action="needs_review",
        evidence_citations=[],
        actionable_observables=[],
        priority_band="P2",
        priority_reasoning=(
            "Stage 4 LLM call failed — priority defaulted to P2 to ensure human review. "
            "A failed pipeline cannot safely be treated as low-risk."
        ),
        investigation_gaps=[
            "Stage 4 LLM failed — complete manual triage required. "
            "No automated assessment was produced."
        ],
    )
