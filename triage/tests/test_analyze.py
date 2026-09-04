"""`analyst_verdict` — Stage 4, architecture §9. The second and LAST of exactly
2 LLM calls in the whole pipeline.

PROVENANCE: `tests/fixtures/analyze_live_run_real.json` is REAL — the first
live `nodes.analyze.analyst_verdict` call ever made in this repo, 2026-08-21.
`evidence` is a fresh, real `gather_evidence` + `rag_enrichment` run against
the real xordump/Invoke-WebRequest alert (`sigma-alert-sample.json`).
`context` is REUSED from `tests/fixtures/context_live_run_fixed_real.json`
(captured 2026-08-16, same alert, post `merge_into_case_id` fix) rather than
re-running Stage 3 — avoids a redundant ~300s CPU call for a fixture whose
only job is exercising Stage 4. See the fixture's own `"note"` field for the
full provenance statement, including why the evidence/context timing gap
doesn't affect correctness (`analyst_verdict` trusts `context` as an
already-decided input, never cross-checks it against `evidence.open_cases`).
Real wall-clock: 81.2s. The fallback path was also deliberately triggered
live (pointing `config.LLM_ANALYZE_BASE_URL` at an unreachable port, per
implementation guide §5) and confirmed a 0.162s, non-crashing
`TriageVerdict(verdict="needs_review", ...)` matching architecture §9's exact
worked fallback values.

Everything else here mocks `nodes.analyze._call_llm` or
`httpx.AsyncClient.post` directly and checks orchestration logic only: JSON
extraction, fallback routing, dynamic schema construction, and the
`recommended_action` defense-in-depth validator.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

import config
from nodes import analyze as analyze_mod
from schemas import (
    ActionableObservable,
    AssetContext,
    CanonicalAlert,
    ClosedCasesSummary,
    ContextualAssessment,
    CorrelationDecision,
    EnrichedEvidence,
    EvidenceSituation,
    ExtractedObservable,
    ExtractedObservables,
    Host,
    PlaybookMatch,
    Observables,
    RawEvidence,
    Rule,
    RuleContext,
    TriageVerdict,
    User,
)

FIXTURE = Path(__file__).parent / "fixtures" / "analyze_live_run_real.json"
CONTEXT_FIXTURE = Path(__file__).parent / "fixtures" / "context_live_run_fixed_real.json"


@pytest.fixture(scope="module")
def real() -> dict:
    """REAL — one live nodes.analyze.analyst_verdict run, captured 2026-08-21."""
    return json.loads(FIXTURE.read_text())


@pytest.fixture(scope="module")
def real_context() -> ContextualAssessment:
    """REAL — the ContextualAssessment fed into the run captured above (see
    module docstring for why it's reused rather than freshly re-run).

    v5 schema patch: `context_live_run_fixed_real.json` was captured
    2026-08-16, before the v5 redesign (`newdesign.md`) — it carries the
    now-removed `contextual_modifiers`/`confidence`/`llm_criticality_score`
    and lacks the now-required `evidence_situation`. Everything else in the
    real capture (refined_mitre_mapping, correlation_decision,
    extracted_observables) is used byte-for-byte, unmodified — only the
    envelope is patched to satisfy the current schema. A fresh live Stage 3
    capture under the v5 prompt/schema is the real follow-up
    (`newdesign.md` §11 step 5), not a substitute for it."""
    raw = json.loads(CONTEXT_FIXTURE.read_text())
    patched = dict(raw["parsed_assessment"])
    for legacy_field in ("contextual_modifiers", "confidence", "llm_criticality_score"):
        patched.pop(legacy_field, None)
    patched["evidence_situation"] = {
        "sources": [],
        "overall_evidence_reliability": "high",
        "analyst_must_verify": [],
    }
    return ContextualAssessment.model_validate(patched)


@pytest.fixture(autouse=True)
def no_real_playbook_retrieval(monkeypatch):
    """Every test in this file gets a clean, explicit Qdrant mock by
    default — without this, nodes.analyze.qdrant.retrieve_playbooks makes a
    REAL network call every time the full analyst_verdict path runs, which
    in some tests here was previously only "safe" by accident (a shared
    httpx.AsyncClient.post mock meant for the LLM call also intercepted
    Qdrant's call with a mismatched signature, producing a TypeError that
    retrieve_playbooks' own NEVER RAISES contract happened to swallow into a
    Gap). Tests that care about playbook-retrieval behavior specifically
    (TestRunbookRetrieval) override this per-test."""

    async def fake_retrieve_playbooks(query_text, top_k=3, timeout=None):
        return [], None

    monkeypatch.setattr(analyze_mod.qdrant, "retrieve_playbooks", fake_retrieve_playbooks)


def run(coro):
    return asyncio.run(coro)


def make_alert(**overrides) -> CanonicalAlert:
    defaults = dict(
        alert_id="~1",
        timestamp=datetime.now(timezone.utc),
        rule=Rule(name="Suspicious Invoke-WebRequest Execution", uuid="5e3cc4d8-…"),
        host=Host(hostname="win-kvkmd51ggkq"),
        user=User(name="Administrator"),
    )
    defaults.update(overrides)
    return CanonicalAlert(**defaults)


def make_evidence(*, rule_context: RuleContext | None = None) -> EnrichedEvidence:
    raw = RawEvidence(canonical_alert=make_alert(), rule_context=rule_context)
    return EnrichedEvidence(**raw.model_dump())


def make_evidence_situation(**overrides) -> EvidenceSituation:
    defaults = dict(sources=[], overall_evidence_reliability="high", analyst_must_verify=[])
    defaults.update(overrides)
    return EvidenceSituation(**defaults)


def make_context(
    *,
    action: str = "new",
    merge_into_case_id: str | None = None,
    extracted_observables: ExtractedObservables | None = None,
    evidence_situation: EvidenceSituation | None = None,
) -> ContextualAssessment:
    return ContextualAssessment(
        correlation_decision=CorrelationDecision(
            action=action, merge_into_case_id=merge_into_case_id, reasoning="test"
        ),
        extracted_observables=extracted_observables or ExtractedObservables(),
        evidence_situation=evidence_situation or make_evidence_situation(),
    )


def fake_response(content: str, status_code: int = 200) -> httpx.Response:
    request = httpx.Request("POST", "http://fake-ollama/v1/chat/completions")
    return httpx.Response(
        status_code,
        json={"choices": [{"message": {"content": content}}]},
        request=request,
    )


GOOD_VERDICT_JSON = json.dumps(
    {
        "likelihood": "likely",
        "impact_if_true": "significant",
        "verdict": "true_positive",
        "reasoning": "test reasoning",
        "summary": "test summary",
        "recommended_action": "create_case",
        "evidence_citations": ["rule_context.severity=high"],
        "actionable_observables": [],
        # v5 (newdesign.md §4) — priority_band/priority_reasoning are
        # required LLM outputs now; investigation_gaps defaults to [] but is
        # included for clarity.
        "priority_band": "P3",
        "priority_reasoning": "test priority reasoning",
        "investigation_gaps": [],
    }
)


class TestHappyPath:
    def test_well_formed_response_parses_and_is_returned(self, monkeypatch):
        async def fake_post(self, url, *, headers, json, timeout):
            return fake_response(GOOD_VERDICT_JSON)

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        verdict = run(analyze_mod.analyst_verdict(make_context(), make_evidence()))

        assert verdict.verdict == "true_positive"
        assert verdict.recommended_action == "create_case"
        assert verdict.stage_4_duration_ms >= 0

    def test_request_uses_analyze_config_not_stage_3_config(self, monkeypatch):
        """A real bug this test would catch: nodes/analyze.py copy-pasting
        config.LLM_BASE_URL/LLM_MODEL/STAGE_3_LLM_TIMEOUT from nodes/context.py
        instead of the LLM_ANALYZE_*/STAGE_4_LLM_TIMEOUT values."""
        captured = {}

        async def fake_post(self, url, *, headers, json, timeout):
            captured["url"] = url
            captured["json"] = json
            captured["timeout"] = timeout
            return fake_response(GOOD_VERDICT_JSON)

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
        run(analyze_mod.analyst_verdict(make_context(), make_evidence()))

        assert captured["url"] == f"{config.LLM_ANALYZE_BASE_URL}/chat/completions"
        assert captured["json"]["model"] == config.LLM_ANALYZE_MODEL
        assert captured["json"]["response_format"]["type"] == "json_schema"
        assert captured["timeout"] == config.STAGE_4_LLM_TIMEOUT


class TestCappedMaxTokens:
    """Mirrors tests.test_context.TestCappedMaxTokens for Stage 4's identical
    fix — see nodes/analyze.py's module docstring and config.py's
    LLM_MAX_CONTEXT_TOKENS/LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN/
    LLM_CONTEXT_SAFETY_MARGIN_TOKENS."""

    def test_small_prompt_gets_the_desired_value_unchanged(self):
        result = analyze_mod._capped_max_tokens("short system", "short user", desired=2000)
        assert result == 2000

    def test_large_prompt_gets_capped_below_desired(self, monkeypatch):
        # Pinned to 8192 for the same reason as tests.test_context's
        # equivalent test: .env's Gemini-session LLM_MAX_CONTEXT_TOKENS
        # override (~1M) would otherwise stop this prompt size from
        # triggering a cap at all.
        monkeypatch.setattr(config, "LLM_MAX_CONTEXT_TOKENS", 8192)
        # sized to estimate to ~6500 tokens -- Stage 4's desired ceiling is
        # only 2000, so a smaller prompt than Stage 3's equivalent test
        # already leaves headroom below 2000; this one doesn't.
        large_user_prompt = "x" * int(6500 * config.LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN)
        result = analyze_mod._capped_max_tokens("short system", large_user_prompt, desired=2000)
        assert result < 2000

        estimated_prompt_tokens = len("short system" + large_user_prompt) / config.LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN
        assert estimated_prompt_tokens + result + config.LLM_CONTEXT_SAFETY_MARGIN_TOKENS <= config.LLM_MAX_CONTEXT_TOKENS

    def test_extreme_prompt_floors_at_the_minimum_rather_than_going_negative(self, monkeypatch):
        monkeypatch.setattr(config, "LLM_MAX_CONTEXT_TOKENS", 8192)
        enormous_prompt = "x" * 100_000
        result = analyze_mod._capped_max_tokens("", enormous_prompt, desired=2000)
        assert result == config.LLM_MIN_COMPLETION_TOKENS

    def test_payload_max_tokens_reflects_the_cap(self, monkeypatch):
        monkeypatch.setattr(config, "LLM_MAX_CONTEXT_TOKENS", 8192)
        captured = {}

        async def fake_post(self, url, *, headers, json, timeout):
            captured["json"] = json
            return fake_response(GOOD_VERDICT_JSON)

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
        evidence = make_evidence(rule_context=RuleContext(found=True, description="x" * 30_000))
        run(analyze_mod.analyst_verdict(make_context(), evidence))

        assert captured["json"]["max_tokens"] < config.STAGE_4_DESIRED_MAX_TOKENS

    def test_call_llm_uses_configured_desired_value_not_a_hardcoded_literal(self, monkeypatch):
        """Mirrors tests.test_context's identical 2026-08-23 regression guard
        — Stage 4's desired max_tokens is config.STAGE_4_DESIRED_MAX_TOKENS,
        not a bare literal. Small prompt -> uncapped -> payload's max_tokens
        must equal whatever config says."""
        monkeypatch.setattr(config, "STAGE_4_DESIRED_MAX_TOKENS", 3333)
        captured = {}

        async def fake_post(self, url, *, headers, json, timeout):
            captured["json"] = json
            return fake_response(GOOD_VERDICT_JSON)

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
        evidence = make_evidence(rule_context=RuleContext(found=True, description="short"))
        run(analyze_mod.analyst_verdict(make_context(), evidence))

        assert captured["json"]["max_tokens"] == 3333


class TestSelfContinuationIsHandled:
    """Same live-observed failure mode Stage 3 defends against — see
    nodes/context.py's identical function and CLAUDE.md's write-up."""

    def test_extracts_only_the_first_json_object(self):
        content = (
            '{"verdict":"needs_review","note":"ok"}\n\n'
            "Would you like another?yes\n\n"
            'Some more text.\n\n{"verdict":"true_positive","note":"other"}'
        )
        parsed = analyze_mod._extract_first_json_object(content)
        assert parsed == {"verdict": "needs_review", "note": "ok"}

    def test_handles_leading_and_trailing_whitespace(self):
        content = '  \n  {"verdict":"needs_review"}  \n  trailing garbage'
        parsed = analyze_mod._extract_first_json_object(content)
        assert parsed == {"verdict": "needs_review"}


class TestFallbackPaths:
    """Every failure class funnels to the same deterministic fallback — never
    an unhandled exception reaching analyst_verdict's caller."""

    def test_connection_error(self, monkeypatch):
        async def raising_call_llm(context, evidence):
            raise httpx.ConnectError("simulated: connection refused")

        monkeypatch.setattr(analyze_mod, "_call_llm", raising_call_llm)
        verdict = run(analyze_mod.analyst_verdict(make_context(), make_evidence()))
        assert verdict.verdict == "needs_review"

    def test_read_timeout(self, monkeypatch):
        async def raising_call_llm(context, evidence):
            raise httpx.ReadTimeout("simulated: timed out")

        monkeypatch.setattr(analyze_mod, "_call_llm", raising_call_llm)
        verdict = run(analyze_mod.analyst_verdict(make_context(), make_evidence()))
        assert verdict.verdict == "needs_review"

    def test_non_2xx_status(self, monkeypatch):
        async def raising_call_llm(context, evidence):
            request = httpx.Request("POST", "http://fake")
            response = httpx.Response(500, request=request)
            raise httpx.HTTPStatusError("simulated 500", request=request, response=response)

        monkeypatch.setattr(analyze_mod, "_call_llm", raising_call_llm)
        verdict = run(analyze_mod.analyst_verdict(make_context(), make_evidence()))
        assert verdict.verdict == "needs_review"

    def test_malformed_json_body(self, monkeypatch):
        async def bad_call_llm(context, evidence):
            return "this is not json at all"

        monkeypatch.setattr(analyze_mod, "_call_llm", bad_call_llm)
        verdict = run(analyze_mod.analyst_verdict(make_context(), make_evidence()))
        assert verdict.verdict == "needs_review"

    def test_json_fails_pydantic_validation(self, monkeypatch):
        async def bad_call_llm(context, evidence):
            return json.dumps({"likelihood": "extremely likely", "not_a_real_field": True})

        monkeypatch.setattr(analyze_mod, "_call_llm", bad_call_llm)
        verdict = run(analyze_mod.analyst_verdict(make_context(), make_evidence()))
        assert verdict.verdict == "needs_review"

    def test_fallback_matches_architecture_worked_example(self, monkeypatch):
        """Regression guard — architecture §9's exact fallback literal
        values, not just "some" needs_review verdict."""

        async def raising_call_llm(context, evidence):
            raise httpx.ConnectError("simulated")

        monkeypatch.setattr(analyze_mod, "_call_llm", raising_call_llm)
        verdict = run(analyze_mod.analyst_verdict(make_context(), make_evidence()))

        assert verdict.likelihood == "possible"
        assert verdict.impact_if_true == "moderate"
        assert verdict.verdict == "needs_review"
        assert verdict.recommended_action == "needs_review"
        assert verdict.evidence_citations == []
        # v5 (newdesign.md §4) — fallback defaults to P2, not P3: a failed
        # pipeline has no verdict at all and must not be treated as low-risk.
        assert verdict.priority_band == "P2"
        assert "P2" in verdict.priority_reasoning
        assert len(verdict.investigation_gaps) >= 1


class TestSchemaStaysInSync:
    def test_hand_inlined_schema_matches_pydantic_model_fields(self):
        """Guards against prompts.analyst_agent._BASE_SCHEMA silently
        drifting from TriageVerdict after a future field change — see
        prompts/analyst_agent.py's module docstring."""
        import prompts.analyst_agent as agent_prompts

        pydantic_schema = TriageVerdict.model_json_schema()
        hand_schema = agent_prompts.build_triage_verdict_schema(make_context(), make_evidence())

        # stage_4_duration_ms, runbook_matches, and safety_gate_applied are
        # all set by nodes/analyze.py AFTER the LLM call returns (the last
        # one by _apply_safety_backstop, v5 — see schemas/verdict.py) —
        # never fields the LLM is asked to fill in.
        llm_facing_fields = set(pydantic_schema["properties"].keys()) - {
            "stage_4_duration_ms",
            "runbook_matches",
            "safety_gate_applied",
        }
        assert llm_facing_fields == set(hand_schema["properties"].keys())


class TestDynamicRecommendedActionSchema:
    """Regression guard for the class of bug Stage 3's merge_into_case_id fix
    closed: recommended_action's enum must exclude branches that contradict
    correlation_decision.action, making the wrong answer structurally
    unrepresentable."""

    def test_merge_action_excludes_create_case(self):
        import prompts.analyst_agent as agent_prompts

        schema = agent_prompts.build_triage_verdict_schema(
            make_context(action="merge"), make_evidence()
        )
        enum = schema["properties"]["recommended_action"]["enum"]
        assert "create_case" not in enum
        assert set(enum) == {"merge_quiet", "merge_and_retier", "close_fp", "needs_review"}

    def test_new_action_excludes_merge_options(self):
        import prompts.analyst_agent as agent_prompts

        schema = agent_prompts.build_triage_verdict_schema(
            make_context(action="new"), make_evidence()
        )
        enum = schema["properties"]["recommended_action"]["enum"]
        assert "merge_quiet" not in enum
        assert "merge_and_retier" not in enum
        assert set(enum) == {"create_case", "close_fp", "needs_review"}

    def test_base_schema_template_is_never_mutated(self):
        """build_triage_verdict_schema must deep-copy — two calls with
        different context must not leak enum values into each other via a
        shared mutable dict."""
        import prompts.analyst_agent as agent_prompts

        agent_prompts.build_triage_verdict_schema(make_context(action="merge"), make_evidence())
        fresh = agent_prompts.build_triage_verdict_schema(
            make_context(action="new"), make_evidence()
        )
        enum = fresh["properties"]["recommended_action"]["enum"]
        assert "merge_quiet" not in enum


class TestRecommendedActionValidation:
    """Defense-in-depth behind the schema constraint — exercises
    nodes.analyze._validate_recommended_action directly, bypassing schema
    enforcement entirely to prove the safety net holds independently of it."""

    def test_valid_action_is_kept(self):
        verdict = TriageVerdict(
            likelihood="likely",
            impact_if_true="significant",
            verdict="true_positive",
            reasoning="x",
            summary="x",
            recommended_action="merge_quiet",
            priority_band="P3",
            priority_reasoning="test",
        )
        context = make_context(action="merge")

        result = analyze_mod._validate_recommended_action(verdict, context)

        assert result.recommended_action == "merge_quiet"

    def test_create_case_discarded_when_action_is_merge(self):
        verdict = TriageVerdict(
            likelihood="likely",
            impact_if_true="significant",
            verdict="true_positive",
            reasoning="x",
            summary="x",
            recommended_action="create_case",
            priority_band="P3",
            priority_reasoning="test",
        )
        context = make_context(action="merge")

        result = analyze_mod._validate_recommended_action(verdict, context)

        assert result.recommended_action == "needs_review"

    def test_merge_options_discarded_when_action_is_new(self):
        for bad_action in ("merge_quiet", "merge_and_retier"):
            verdict = TriageVerdict(
                likelihood="likely",
                impact_if_true="significant",
                verdict="true_positive",
                reasoning="x",
                summary="x",
                recommended_action=bad_action,
                priority_band="P3",
                priority_reasoning="test",
            )
            context = make_context(action="new")

            result = analyze_mod._validate_recommended_action(verdict, context)

            assert result.recommended_action == "needs_review"

    def test_close_fp_and_needs_review_always_valid(self):
        for action in ("new", "merge"):
            for candidate in ("close_fp", "needs_review"):
                verdict = TriageVerdict(
                    likelihood="unlikely",
                    impact_if_true="minor",
                    verdict="false_positive",
                    reasoning="x",
                    summary="x",
                    recommended_action=candidate,
                    priority_band="P3",
                    priority_reasoning="test",
                )
                result = analyze_mod._validate_recommended_action(verdict, make_context(action=action))
                assert result.recommended_action == candidate

    def test_end_to_end_through_analyst_verdict(self, monkeypatch):
        """The full path: a mocked LLM response proposing an incompatible
        recommended_action gets corrected by the real analyst_verdict flow,
        not just the standalone validator."""
        bad_content = json.dumps(
            {
                "likelihood": "likely",
                "impact_if_true": "significant",
                "verdict": "true_positive",
                "reasoning": "x",
                "summary": "x",
                "recommended_action": "create_case",
                "evidence_citations": [],
                "actionable_observables": [],
                "priority_band": "P3",
                "priority_reasoning": "test",
            }
        )

        async def fake_post(self, url, *, headers, json, timeout):
            return fake_response(bad_content)

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
        verdict = run(analyze_mod.analyst_verdict(make_context(action="merge"), make_evidence()))

        assert verdict.recommended_action == "needs_review"


class TestActionableObservablesValidation:
    """Mirrors tests.test_context.TestExtractedObservablesValidation for
    nodes.analyze._validate_actionable_observables — same defense-in-depth
    role, same escaping-safe check (CLAUDE.md 2026-08-23), scoped to the
    three sources TASK 5 names (known/extracted/case observables) instead of
    the full evidence Stage 4 never sees."""

    def test_value_traceable_to_known_observables_is_kept(self):
        alert = make_alert(observables=Observables(external_ips=["1.2.3.4"]))
        evidence = EnrichedEvidence(**RawEvidence(canonical_alert=alert).model_dump())
        context = make_context()
        verdict = TriageVerdict(
            likelihood="likely",
            impact_if_true="significant",
            verdict="true_positive",
            reasoning="x",
            summary="x",
            recommended_action="create_case",
            actionable_observables=[
                ActionableObservable(
                    observable_type="ip",
                    value="1.2.3.4",
                    recommended_disposition="block",
                    confidence="high",
                    reasoning="known malicious C2",
                )
            ],
            priority_band="P3",
            priority_reasoning="test",
        )
        result = analyze_mod._validate_actionable_observables(verdict, context, evidence, [])
        assert len(result.actionable_observables) == 1

    def test_value_traceable_to_extracted_observables_is_kept(self):
        evidence = make_evidence()
        context = make_context(
            extracted_observables=ExtractedObservables(
                process=[
                    ExtractedObservable(
                        observable_type="process-path",
                        value="C:\\Windows\\Temp\\xordump.exe",
                        rationale="dropped in temp",
                        confidence="high",
                        source="behavioral_analysis",
                    )
                ]
            )
        )
        verdict = TriageVerdict(
            likelihood="likely",
            impact_if_true="significant",
            verdict="true_positive",
            reasoning="x",
            summary="x",
            recommended_action="create_case",
            actionable_observables=[
                ActionableObservable(
                    observable_type="process-path",
                    value="C:\\Windows\\Temp\\xordump.exe",
                    recommended_disposition="quarantine",
                    confidence="medium",
                    reasoning="matches Stage 3 extraction",
                )
            ],
            priority_band="P3",
            priority_reasoning="test",
        )
        # a backslash-bearing value from a DIFFERENT source than
        # canonical_alert.observables — regression coverage for the
        # escaping fix on this new, second call site.
        result = analyze_mod._validate_actionable_observables(verdict, context, evidence, [])
        assert len(result.actionable_observables) == 1

    def test_value_traceable_to_case_observables_is_kept(self):
        evidence = make_evidence()
        context = make_context(action="merge", merge_into_case_id="~123")
        case_observables = [{"data_type": "hash", "value": "deadbeef" * 8, "tags": []}]
        verdict = TriageVerdict(
            likelihood="likely",
            impact_if_true="significant",
            verdict="true_positive",
            reasoning="x",
            summary="x",
            recommended_action="merge_quiet",
            actionable_observables=[
                ActionableObservable(
                    observable_type="hash",
                    value="deadbeef" * 8,
                    recommended_disposition="block",
                    confidence="high",
                    reasoning="already on the target case",
                )
            ],
            priority_band="P3",
            priority_reasoning="test",
        )
        result = analyze_mod._validate_actionable_observables(
            verdict, context, evidence, case_observables
        )
        assert len(result.actionable_observables) == 1

    def test_fabricated_value_is_discarded(self):
        evidence = make_evidence()
        context = make_context()
        verdict = TriageVerdict(
            likelihood="likely",
            impact_if_true="significant",
            verdict="true_positive",
            reasoning="x",
            summary="x",
            recommended_action="create_case",
            actionable_observables=[
                ActionableObservable(
                    observable_type="ip",
                    value="9.9.9.9",  # not present anywhere
                    recommended_disposition="block",
                    confidence="low",
                    reasoning="invented",
                )
            ],
            priority_band="P3",
            priority_reasoning="test",
        )
        result = analyze_mod._validate_actionable_observables(verdict, context, evidence, [])
        assert result.actionable_observables == []


class TestCaseObservablesFetch:
    """The new non-LLM call nodes/analyze.py makes on a merge, before
    building Stage 4's prompt — see CLAUDE.md's 2026-08-23 build writeup."""

    def test_fetch_called_only_on_merge_with_a_target_case(self, monkeypatch):
        calls = []

        async def fake_fetch(case_id, timeout=None):
            calls.append(case_id)
            return [{"data_type": "ip", "value": "5.5.5.5", "tags": []}], None

        monkeypatch.setattr(analyze_mod.thehive, "fetch_case_observables_with_type", fake_fetch)

        async def fake_post(self, url, *, headers, json, timeout):
            return fake_response(GOOD_VERDICT_JSON)

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        run(analyze_mod.analyst_verdict(make_context(action="new"), make_evidence()))
        assert calls == []

        run(
            analyze_mod.analyst_verdict(
                make_context(action="merge", merge_into_case_id="~456"), make_evidence()
            )
        )
        assert calls == ["~456"]

    def test_fetch_failure_still_produces_a_valid_verdict(self, monkeypatch):
        """NEVER RAISES contract: a Gap from the fetch must not crash Stage 4
        — proceeds with case_observables=[] like a "new" alert would."""

        async def failing_fetch(case_id, timeout=None):
            from schemas import Gap

            return [], Gap(source="thehive", tool="fetch_case_observables_with_type", reason="down")

        monkeypatch.setattr(analyze_mod.thehive, "fetch_case_observables_with_type", failing_fetch)

        async def fake_post(self, url, *, headers, json, timeout):
            return fake_response(GOOD_VERDICT_JSON)

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        verdict = run(
            analyze_mod.analyst_verdict(
                make_context(action="merge", merge_into_case_id="~789"), make_evidence()
            )
        )
        assert verdict.verdict == "true_positive"


class TestRunbookRetrieval:
    """The 2026-08-23 addition: tools.qdrant.retrieve_playbooks, queried from
    Stage 3's refined MITRE mapping, fetched before the LLM call and set
    onto verdict.runbook_matches post-hoc (see module docstring)."""

    def test_build_playbook_query_uses_rule_title_and_refined_mapping(self):
        from schemas import MitreMapping

        alert = make_alert(rule=Rule(name="Suspicious Invoke-WebRequest Execution", uuid="x"))
        evidence = EnrichedEvidence(**RawEvidence(canonical_alert=alert).model_dump())
        context = make_context(
            extracted_observables=ExtractedObservables(),
        )
        context.refined_mitre_mapping = [
            MitreMapping(technique_id="T1105", technique_name="Ingress Tool Transfer",
                          tactic="Command and Control", confidence="high"),
        ]

        query = analyze_mod._build_playbook_query(context, evidence)

        assert "Suspicious Invoke-WebRequest Execution" in query
        assert "T1105" in query
        assert "Ingress Tool Transfer" in query
        assert "Command and Control" in query

    def test_build_playbook_query_falls_back_to_rule_title_alone(self):
        alert = make_alert(rule=Rule(name="Some Rule", uuid="x"))
        evidence = EnrichedEvidence(**RawEvidence(canonical_alert=alert).model_dump())
        context = make_context()  # no refined_mitre_mapping

        query = analyze_mod._build_playbook_query(context, evidence)

        assert query == "Some Rule"

    def test_retrieval_result_lands_on_verdict_runbook_matches(self, monkeypatch):
        hit = PlaybookMatch(
            playbook_id="pb-1",
            title="Suspicious Ingress Tool Transfer",
            category="command-and-control",
            section="Containment",
            document_text="Block the destination IP and quarantine the binary.",
            score=0.87,
        )

        async def fake_retrieve(query_text, top_k=3, timeout=None):
            return [hit], None

        monkeypatch.setattr(analyze_mod.qdrant, "retrieve_playbooks", fake_retrieve)

        async def fake_post(self, url, *, headers, json, timeout):
            return fake_response(GOOD_VERDICT_JSON)

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        verdict = run(analyze_mod.analyst_verdict(make_context(), make_evidence()))

        assert len(verdict.runbook_matches) == 1
        assert verdict.runbook_matches[0].title == "Suspicious Ingress Tool Transfer"

    def test_retrieval_gap_still_produces_a_valid_verdict(self, monkeypatch):
        from schemas import Gap

        async def failing_retrieve(query_text, top_k=3, timeout=None):
            return [], Gap(source="qdrant", tool="retrieve_playbooks", reason="down")

        monkeypatch.setattr(analyze_mod.qdrant, "retrieve_playbooks", failing_retrieve)

        async def fake_post(self, url, *, headers, json, timeout):
            return fake_response(GOOD_VERDICT_JSON)

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        verdict = run(analyze_mod.analyst_verdict(make_context(), make_evidence()))

        assert verdict.verdict == "true_positive"
        assert verdict.runbook_matches == []

    def test_runbook_matches_attached_even_on_llm_fallback(self, monkeypatch):
        """runbook_matches is independent of whether the LLM call itself
        succeeded — attached post-hoc regardless of which branch produced
        the verdict (real parse or _stage_4_fallback)."""
        hit = PlaybookMatch(playbook_id="pb-1", title="x", document_text="x")

        async def fake_retrieve(query_text, top_k=3, timeout=None):
            return [hit], None

        monkeypatch.setattr(analyze_mod.qdrant, "retrieve_playbooks", fake_retrieve)

        async def raises_post(self, url, *, headers, json, timeout):
            raise httpx.ConnectError("refused")

        monkeypatch.setattr(httpx.AsyncClient, "post", raises_post)

        verdict = run(analyze_mod.analyst_verdict(make_context(), make_evidence()))

        assert verdict.reasoning == "Stage 4 LLM unavailable, defaulting to human review"
        assert len(verdict.runbook_matches) == 1


class TestSummarizeEvidenceFirewall:
    """architecture §9: Stage 4 must see a sanitized summary, never raw log
    lines, full command lines, or Cortex report bodies beyond 300 chars."""

    def _rich_evidence(self) -> EnrichedEvidence:
        from schemas import CortexResult, Process

        alert = make_alert().model_copy(
            update={
                "process": Process(
                    name="powershell.exe",
                    command_line="SECRET_COMMAND_LINE_MARKER powershell -enc AAAA",
                )
            }
        )
        raw = RawEvidence(canonical_alert=alert)
        evidence = EnrichedEvidence(**raw.model_dump())
        evidence.canonical_alert.cortex_results = [
            CortexResult(
                observable="1.2.3.4",
                type="ip",
                verdict=["malicious"],
                details="X" * 500,  # long report body — must be truncated to 300
                analyzer="VirusTotal",
            )
        ]
        return evidence

    def test_command_line_never_appears_in_summary(self):
        import prompts.analyst_agent as agent_prompts

        evidence = self._rich_evidence()
        rendered = agent_prompts.build_user_prompt(make_context(), evidence, [], [])
        assert "SECRET_COMMAND_LINE_MARKER" not in rendered

    def test_cortex_details_truncated_to_300_chars(self):
        import prompts.analyst_agent as agent_prompts

        evidence = self._rich_evidence()
        summary = agent_prompts._summarize_evidence(make_context(), evidence, [], [])
        assert len(summary["threat_intel"][0]["details_truncated_300"]) == 300

    def test_temporal_and_historical_context_are_counts(self):
        import prompts.analyst_agent as agent_prompts

        evidence = make_evidence()
        summary = agent_prompts._summarize_evidence(make_context(), evidence, [], [])
        assert summary["temporal_context"]["total_related_alerts"] == 0
        assert "tp_count" in summary["historical_context"]
        assert "fp_count" in summary["historical_context"]


def _patched_parsed_verdict(real: dict) -> dict:
    """`analyze_live_run_real.json`'s `parsed_verdict` was captured
    2026-08-21, before the v5 redesign (`newdesign.md`) added the required
    `priority_band`/`priority_reasoning` fields. Everything else in the real
    capture is used byte-for-byte, unmodified — only the two new required
    fields are patched in, since replaying this exact real response through
    the current schema needs no less. A fresh live Stage 4 capture under the
    v5 prompt/schema is the real follow-up (`newdesign.md` §11 step 5)."""
    patched = dict(real["parsed_verdict"])
    patched.setdefault("priority_band", "P3")
    patched.setdefault("priority_reasoning", "test")
    return patched


class TestRealFixtureLooksReasonable:
    def test_parsed_verdict_validates(self, real):
        verdict = TriageVerdict.model_validate(_patched_parsed_verdict(real))
        assert verdict.stage_4_duration_ms > 0

    def test_recommended_action_consistent_with_captured_context_action(
        self, real, real_context
    ):
        verdict = TriageVerdict.model_validate(_patched_parsed_verdict(real))
        action = real_context.correlation_decision.action
        result = analyze_mod._validate_recommended_action(verdict, real_context)
        # The real model already complied with the constrained schema —
        # the validator must be a no-op on real, well-formed output.
        assert result.recommended_action == verdict.recommended_action
        if action == "new":
            assert verdict.recommended_action != "merge_quiet"
            assert verdict.recommended_action != "merge_and_retier"

    def test_schema_enum_matches_captured_action(self, real):
        assert real["schema_recommended_action_enum"] == ["create_case", "close_fp", "needs_review"]

    def test_wall_clock_within_configured_timeout(self, real):
        assert real["wall_clock_seconds"] < config.STAGE_4_LLM_TIMEOUT

    def test_no_placeholder_literals(self, real):
        verdict_text = json.dumps(real["parsed_verdict"])
        for placeholder in ("TODO", "PLACEHOLDER", "<unset>"):
            assert placeholder not in verdict_text
