"""`context_analysis` — Stage 3, architecture §8. First of exactly 2 LLM
calls in the whole pipeline (CLAUDE.md hard constraint). Single-shot, no
tools: builds a prompt from the full `EnrichedEvidence`, calls the LLM once,
parses/validates its response, and never raises to its caller — any failure
(connection error, timeout, non-2xx status, malformed JSON, a response that
fails Pydantic validation) produces the same kind of deterministic
`ContextualAssessment` fallback instead.

Not built on `nodes/_guard.py`. `_guarded`'s `default` parameter is a
static value; this node's fallback (`_stage_3_fallback`) is a function of
the input `evidence`, which `_guarded`'s signature can't express cleanly.
`gather.py`/`rag.py` also each wrap several *parallel* calls behind one
shared timeout pattern; this node makes exactly one call, so the
"outer wait_for + inner tool timeout" two-layer defense doesn't apply the
same way either — `httpx`'s own `timeout=` on the request is the only
layer needed here, and reliably raises `httpx.ReadTimeout` at that bound
(live-verified: a broken, hanging call died with exactly that exception at
the configured timeout, not an indefinite hang).

`config.STAGE_3_LLM_TIMEOUT` is set generously in this deployment's `.env`
(600s) because the Ollama host runs the model on CPU during development —
see `.env`'s comment and REPO-STATUS.md. That is a config value only; no
line in this module branches on CPU vs GPU.

**2026-08-23 fix — `_capped_max_tokens`.** Live-caught: a real, evidence-rich
alert's prompt (4193 real tokens, confirmed by the backend's own error
message) plus the previously-fixed `max_tokens=4000` exceeded this model's
8192-token context window, and the call failed with a real 400 — Stage 3
fell back gracefully, but silently lost its LLM refinement entirely on any
alert rich enough to trigger it. `max_tokens` is now capped against the
actual built prompt's estimated size before every call — see
`config.py`'s `LLM_MAX_CONTEXT_TOKENS`/`LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN`/
`LLM_CONTEXT_SAFETY_MARGIN_TOKENS` docstrings for the estimation approach
and why it's deliberately conservative.
"""

from __future__ import annotations

import json
import logging
import time

import httpx

import config
import prompts.context_agent as prompts
from logging_config import alert_context
from schemas import (
    ContextualAssessment,
    CorrelationDecision,
    EnrichedEvidence,
    EvidenceSituation,
    EvidenceSource,
    ExtractedObservables,
    MitreMapping,
    RawEvidence,
)

logger = logging.getLogger(__name__)


async def context_analysis(evidence: EnrichedEvidence) -> ContextualAssessment:
    with alert_context(evidence.canonical_alert.alert_id):
        return await _context_analysis(evidence)


async def _context_analysis(evidence: EnrichedEvidence) -> ContextualAssessment:
    started = time.monotonic()
    logger.info("Stage 3 started")
    try:
        raw_content = await _call_llm(evidence)
        parsed = _extract_first_json_object(raw_content)
        assessment = ContextualAssessment.model_validate(parsed)
        assessment = _validate_merge_target(assessment, evidence)
        assessment = _validate_extracted_observables(assessment, evidence)
    except Exception as exc:  # noqa: BLE001 — see module docstring, every failure falls back
        logger.warning("Stage 3 LLM call/parse failed, using deterministic fallback: %s", exc)
        assessment = _stage_3_fallback(evidence)

    assessment.stage_3_duration_ms = int((time.monotonic() - started) * 1000)
    logger.info(
        "Stage 3 completed in %dms: evidence_reliability=%s action=%s must_verify=%d",
        assessment.stage_3_duration_ms,
        assessment.evidence_situation.overall_evidence_reliability,
        assessment.correlation_decision.action,
        len(assessment.evidence_situation.analyst_must_verify),
    )
    return assessment


def _capped_max_tokens(system_prompt: str, user_prompt: str, desired: int) -> int:
    """Caps the requested completion max_tokens so prompt + completion stays
    under the model's real context window — see config.py's
    LLM_MAX_CONTEXT_TOKENS/LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN/
    LLM_CONTEXT_SAFETY_MARGIN_TOKENS docstrings for the live-caught bug this
    closes and why the estimate is character-based and deliberately
    conservative. Duplicated in nodes/analyze.py rather than shared — same
    reasoning as _extract_first_json_object below: two otherwise-independent
    stage modules, not worth a cross-node dependency for a few lines."""
    estimated_prompt_tokens = len(system_prompt + user_prompt) / config.LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN
    available = (
        config.LLM_MAX_CONTEXT_TOKENS - estimated_prompt_tokens - config.LLM_CONTEXT_SAFETY_MARGIN_TOKENS
    )
    return max(config.LLM_MIN_COMPLETION_TOKENS, min(desired, int(available)))


async def _call_llm(evidence: EnrichedEvidence) -> str:
    user_prompt = prompts.build_user_prompt(evidence)
    max_tokens = _capped_max_tokens(prompts.SYSTEM_PROMPT, user_prompt, config.STAGE_3_DESIRED_MAX_TOKENS)
    payload = {
        "model": config.LLM_MODEL,
        "messages": [
            {"role": "system", "content": prompts.SYSTEM_PROMPT},
            {"role": "user", "content": user_prompt},
        ],
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "ContextualAssessment",
                "schema": prompts.build_contextual_assessment_schema(evidence),
            },
        },
        "temperature": 0.1,
        "max_tokens": max_tokens,
        "stream": False,
    }
    logger.info(
        "Stage 3 LLM call started (model=%s, timeout=%ss, max_tokens=%d)",
        config.LLM_MODEL,
        config.STAGE_3_LLM_TIMEOUT,
        max_tokens,
    )
    llm_started = time.monotonic()
    async with httpx.AsyncClient() as client:
        resp = await client.post(
            f"{config.LLM_BASE_URL}/chat/completions",
            headers={"Authorization": f"Bearer {config.LLM_API_KEY}"},
            json=payload,
            timeout=config.STAGE_3_LLM_TIMEOUT,
        )
        resp.raise_for_status()
        logger.info("Stage 3 LLM call completed in %.1fs", time.monotonic() - llm_started)
        return resp.json()["choices"][0]["message"]["content"]


def _extract_first_json_object(content: str) -> dict:
    """Only the first JSON value in the string is trustworthy. Live-testing
    under plain `json_object` mode showed the model emitting a valid JSON
    object followed by hallucinated extra prose/JSON turns — `json.loads()`
    on the whole string fails or (worse) succeeds on the wrong thing.
    `json_schema` mode didn't reproduce that in testing, but nothing
    guarantees it can't with a different prompt shape, so this stays
    defensive rather than assuming the stricter mode never regresses."""
    return json.JSONDecoder().raw_decode(content.strip())[0]


def _validate_merge_target(
    assessment: ContextualAssessment, evidence: RawEvidence
) -> ContextualAssessment:
    """Defense-in-depth behind the schema-level enum constraint in
    prompts.context_agent.build_contextual_assessment_schema — belt and
    suspenders for the case Ollama's schema enforcement doesn't hold (this
    session already observed model/host variance once: the json_object
    self-continuation). Never called on the fallback path, which sources
    merge_into_case_id directly from evidence.open_cases and is correct by
    construction."""
    merge_id = assessment.correlation_decision.merge_into_case_id
    if merge_id is None:
        return assessment

    real_ids = {case.case_id for case in evidence.open_cases}
    if merge_id not in real_ids:
        logger.warning(
            "Stage 3 proposed merge_into_case_id=%r not in open_cases, discarding", merge_id
        )
        assessment.correlation_decision.merge_into_case_id = None
        assessment.additional_investigation_gaps.append(
            f"LLM proposed merge target {merge_id!r} not present in open_cases — "
            "discarded, treated as new"
        )
    return assessment


_EXTRACTED_OBSERVABLE_BUCKETS = ("process", "file", "external_ips", "domains", "urls", "hash")


def _known_observable_values(evidence: RawEvidence) -> set[str]:
    """Every value n8n's extractor already captured in
    canonical_alert.observables — an extraction that duplicates one of
    these isn't new information, it's the LLM re-deriving what the
    automated pipeline already found."""
    observables = evidence.canonical_alert.observables
    values = set(observables.external_ips) | set(observables.domains) | set(observables.urls)
    hashes = observables.hashes
    values |= set(hashes.md5) | set(hashes.sha1) | set(hashes.sha256)
    values |= set(hashes.sha512) | set(hashes.imphash)
    return values


def _validate_extracted_observables(
    assessment: ContextualAssessment, evidence: RawEvidence
) -> ContextualAssessment:
    """Defense-in-depth for two live-observed failure modes (2026-08-16):
    fabricated values with no basis anywhere in the evidence, and
    re-extracting an IOC n8n's extractor (canonical_alert.observables)
    already captured. The third failure mode observed the same run —
    observable_type not matching its bucket (a "hash" bucket item typed
    "file", etc.) — is closed structurally by the per-bucket enum in
    prompts.context_agent._BUCKET_TO_TYPE, not here; this function can only
    catch what a schema enum can't reach: free-text `value` content."""
    evidence_json = evidence.model_dump_json()
    known_values = _known_observable_values(evidence)
    obs = assessment.extracted_observables

    for bucket in _EXTRACTED_OBSERVABLE_BUCKETS:
        kept = []
        for item in getattr(obs, bucket):
            # item.value is unescaped (json-decoded from the LLM response), but
            # evidence_json is JSON TEXT, where model_dump_json() has already
            # escaped every \ and " it contains. A plain `in` check compares an
            # unescaped needle to an escaped haystack and always misses on any
            # genuinely-correct value containing a backslash or quote — e.g. every
            # Windows path, exactly what the process/file buckets are for. Escape
            # the needle the same way (ensure_ascii=False: Pydantic's serializer
            # emits raw UTF-8, not \uXXXX, for non-ASCII — see CLAUDE.md 2026-08-23)
            # before comparing. Live-caught 2026-08-23: a real xordump.exe path was
            # discarded as a "hallucination" purely from this escaping mismatch.
            needle = json.dumps(item.value, ensure_ascii=False)[1:-1]
            if needle not in evidence_json:
                logger.warning(
                    "Stage 3 extracted_observables.%s value %r not found in evidence, "
                    "discarding as a likely hallucination",
                    bucket,
                    item.value,
                )
                assessment.additional_investigation_gaps.append(
                    f"LLM extracted {bucket} value {item.value!r} not traceable to any "
                    "evidence field — discarded as a likely hallucination"
                )
                continue
            if item.value in known_values:
                logger.info(
                    "Stage 3 extracted_observables.%s value %r duplicates an existing "
                    "canonical_alert.observables entry, discarding",
                    bucket,
                    item.value,
                )
                continue
            kept.append(item)
        setattr(obs, bucket, kept)

    return assessment


_FALLBACK_EVIDENCE_SOURCE_NAMES = (
    "fp_signal",
    "rule_context",
    "open_cases",
    "closed_cases_summary",
    "asset_context",
    "related_alerts_24h",
    "process_history_24h",
    "opencti_enrichment",
)


def _stage_3_fallback(evidence: RawEvidence) -> ContextualAssessment:
    """architecture §8's stage_3_fallback, adapted to this repo's real field
    names. Preserves MITRE mapping from Stage 1's rule lookup — does NOT
    return an empty list (that was v3's silent-severity-cap bug, called out
    by name in architecture §8).

    extracted_observables stays empty — a downed LLM must never fabricate an
    IOC. evidence_situation (v5, `newdesign.md` §3) is built deterministically
    from what Stage 1 actually reported (`evidence.investigation_gaps`),
    mirroring the same distinction TASK 5 draws: a source named in a real
    `Gap` is "missing", everything else is reported "present" (Stage 3 itself
    failed, not Stage 1 — this fallback has no way to know which present
    sources were actually empty vs populated, so it does not claim to)."""
    rule_context = evidence.rule_context
    mitre_attack = rule_context.mitre_attack if rule_context else []

    gap_sources = {g.tool for g in evidence.investigation_gaps}
    sources = []
    for name in _FALLBACK_EVIDENCE_SOURCE_NAMES:
        if name in gap_sources:
            status = "missing"
            impact = f"{name} unavailable — Stage 3 LLM also failed; cannot assess impact."
        else:
            status = "present"
            impact = f"{name} data available but Stage 3 LLM failed — assessment not performed."
        sources.append(EvidenceSource(source_name=name, status=status, impact_on_triage=impact))

    evidence_situation = EvidenceSituation(
        sources=sources,
        overall_evidence_reliability="low",
        analyst_must_verify=[
            "Stage 3 LLM call failed — complete manual review required. "
            "All automated evidence interpretation is unavailable."
        ],
    )

    return ContextualAssessment(
        refined_mitre_mapping=[
            MitreMapping(
                technique_id=technique_id,
                confidence="medium",
                basis="deterministic fallback from rule_context",
            )
            for technique_id in mitre_attack
        ],
        correlation_decision=CorrelationDecision(
            action="merge" if evidence.open_cases else "new",
            merge_into_case_id=evidence.open_cases[0].case_id if evidence.open_cases else None,
            kill_chain_progression_detected=False,
            reasoning="Deterministic fallback: LLM unavailable",
        ),
        additional_investigation_gaps=["Stage 3 LLM call failed"],
        extracted_observables=ExtractedObservables(),
        evidence_situation=evidence_situation,
    )
