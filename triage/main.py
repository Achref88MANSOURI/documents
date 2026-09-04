"""FastAPI HTTP entrypoint — architecture §3, file-tree spec (`main.py #
FastAPI app: POST /triage, POST /feedback, GET /health`). `POST /feedback`
(Stage 6 audit/FP-feedback) is out of scope here — that stage isn't built
yet, see CLAUDE.md.

Orchestrates Stage 1->6 for one real alert, synchronously — architecture's
own deployment checklist ("n8n workflow configured with 300s HTTP timeout on
`/triage`") sizes this as a single blocking request/response, not
fire-and-forget. Stage 0 (dedup) is a confirmed no-op — Redis is not
deployed in this deployment (CLAUDE.md), and architecture §5 requires dedup
absence to never block the pipeline. Nothing to call for it.

**Ingestion, before Stage 1**: n8n's `AlertWebhookPayload`
(`thehive_alert_id`, `raw_alert`, `asset_context`) does NOT carry
`hive_alert` — confirmed via `SOC-3s-IMPLEMENTATION-GUIDE.md` §0.2 and
`alert_builder.build_canonical_alert`'s own docstring ("Observables ... come
from hive_alert, not raw_alert"). This module fetches it itself via
`tools.thehive.get_full_alert_with_analysis` (NEVER RAISES) before calling
`build_canonical_alert`.

**Failure posture, user-directed 2026-08-23**: HTTP 200 always. A failure
produces `TriageResponse(success=False, result=<whatever was built so far>,
error=..., failed_stage=...)` rather than an HTTP error status — n8n's
workflow never breaks on a triage failure, it inspects `success` instead.
Every node from Stage 1 onward already has a documented "never raises to
caller" contract (`gather_evidence`, `rag_enrichment`, `context_analysis`,
`analyst_verdict`, `case_action` — see each module's own docstring), so the
`try/except` here is realistically a safety net for ingestion
(`get_full_alert_with_analysis` also never raises, but `build_canonical_alert`
has no such documented contract) and genuine, unexpected code defects — not
a path expected to fire often. `stage` is tracked explicitly (not inferred
from a traceback) so `failed_stage` is always accurate.

**v5 redesign (`newdesign.md` §5) — Stage 5 is gone.** The pipeline used to
call `nodes/score.py::priority_scoring` (deleted, along with `scoring.py`/
`scoring_config.py`) between Stage 4 and Stage 6. `_build_triage_result`
below replaces it: a thin, math-free function that assembles `TriageResult`
directly from `TriageVerdict`/`ContextualAssessment`/`EnrichedEvidence` — no
"stage" of its own, no node module, since there is no computation left to do
(`priority_band`/`priority_reasoning`/`investigation_gaps` are already
sitting on `verdict`, set entirely by Stage 4's LLM plus its own
`_apply_safety_backstop`).
"""

from __future__ import annotations

import logging
import time

import httpx
from fastapi import FastAPI
from fastapi.responses import JSONResponse

import alert_builder
import config
from logging_config import alert_context
from nodes import analyze as analyze_mod
from nodes import case_action as case_action_mod
from nodes import context as context_mod
from nodes import gather as gather_mod
from nodes import rag as rag_mod
from schemas import (
    AlertWebhookPayload,
    ContextualAssessment,
    EnrichedEvidence,
    TriageResponse,
    TriageResult,
    TriageVerdict,
)
from tools import thehive

logger = logging.getLogger(__name__)

app = FastAPI(title="SOC-3s triage")


def _build_triage_result(
    verdict: TriageVerdict, context: ContextualAssessment, evidence: EnrichedEvidence
) -> TriageResult:
    """Replaces the deleted `nodes/score.py::priority_scoring` (v5,
    `newdesign.md` §5-§6) — no scoring math, just assembly. `priority_band`/
    `priority_reasoning`/`investigation_gaps`/`safety_gate_applied` come
    straight from `verdict`; `evidence_situation` from `context` — both
    already fully computed by Stage 3/4, nothing left for this function to
    derive."""
    started = time.monotonic()
    alert_id = evidence.canonical_alert.alert_id

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
        refined_mitre_mapping=context.refined_mitre_mapping,
        investigation_gaps=verdict.investigation_gaps,
        extracted_observables=context.extracted_observables,
        threat_intel=evidence.canonical_alert.cortex_results,
        runbook_matches=verdict.runbook_matches,
        gathered_evidence=evidence,
        stage_3_assessment=context,
        priority_band=verdict.priority_band,
        priority_reasoning=verdict.priority_reasoning,
        safety_gate_applied=verdict.safety_gate_applied,
        evidence_situation=context.evidence_situation,
        stage_5_duration_ms=int((time.monotonic() - started) * 1000),
    )
    logger.info(
        "Result assembled: priority_band=%s safety_gate_applied=%s",
        result.priority_band,
        result.safety_gate_applied,
    )
    return result


@app.post("/triage", response_model=TriageResponse)
async def triage(payload: AlertWebhookPayload) -> TriageResponse:
    return await run_pipeline(payload)


async def run_pipeline(payload: AlertWebhookPayload) -> TriageResponse:
    stage = "ingest"
    result: TriageResult | None = None

    with alert_context(payload.thehive_alert_id):
        try:
            hive_alert, gap = await thehive.get_full_alert_with_analysis(
                payload.thehive_alert_id
            )
            if gap:
                logger.warning("main: hive_alert fetch degraded: %s", gap.reason)
            alert = alert_builder.build_canonical_alert(
                payload.raw_alert,
                hive_alert,
                payload.asset_context,
                payload.thehive_alert_id,
            )

            stage = "gather"
            raw_evidence = await gather_mod.gather_evidence(alert)

            stage = "rag"
            evidence = await rag_mod.rag_enrichment(raw_evidence)

            stage = "context"
            context = await context_mod.context_analysis(evidence)

            stage = "analyze"
            verdict = await analyze_mod.analyst_verdict(context, evidence)

            stage = "build_result"
            result = _build_triage_result(verdict, context, evidence)

            stage = "case_action"
            result.case_action = await case_action_mod.case_action(verdict, context, evidence)
            # Overwrite with the enriched, ID-populated version — the one
            # Stage 4 alone produced has no observable_id (case_action.py is
            # the only place a real TheHive id can be resolved/created).
            result.actionable_observables = result.case_action.actionable_observables_written

            logger.info(
                "triage completed: alert_id=%s priority_band=%s case_action.success=%s",
                result.alert_id,
                result.priority_band,
                result.case_action.success if result.case_action else None,
            )
            return TriageResponse(success=True, result=result)

        except Exception as exc:  # noqa: BLE001 — see module docstring: HTTP 200 always
            logger.exception(
                "triage pipeline failed at stage=%s for thehive_alert_id=%s",
                stage,
                payload.thehive_alert_id,
            )
            return TriageResponse(
                success=False,
                result=result,
                error=f"{type(exc).__name__}: {exc}",
                failed_stage=stage,
            )


@app.get("/health")
async def health() -> JSONResponse:
    """Cheap reachability check on the LLM backend Stage 3/4 depend on — the
    exact failure mode this session's own vLLM backend-swap test hit twice
    (`.env` pointing at a dead tunnel, then a stale API key, both only
    discovered by attempting a real call). Not a full dependency check
    (ES/TheHive/iTop/Qdrant) — architecture's file-tree spec names `GET
    /health` but doesn't specify its contents; this is deliberately minimal,
    the cheapest check that would have caught both incidents immediately."""
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.get(
                f"{config.LLM_BASE_URL}/models",
                headers={"Authorization": f"Bearer {config.LLM_API_KEY}"},
                timeout=10.0,
            )
        resp.raise_for_status()
        return JSONResponse({"status": "ok", "llm_base_url": config.LLM_BASE_URL})
    except Exception as exc:  # noqa: BLE001 — health check must never itself crash
        return JSONResponse(
            {"status": "degraded", "llm_base_url": config.LLM_BASE_URL, "error": str(exc)},
            status_code=503,
        )
