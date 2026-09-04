"""`context_analysis` — Stage 3, architecture §8. The first of exactly 2 LLM
calls in the whole pipeline.

PROVENANCE: `tests/fixtures/context_live_run_real.json` is REAL — captured by
running `nodes.context.context_analysis` once, end-to-end, no mocking,
against the real `foundation-sec-reasoning:latest` endpoint at
`config.LLM_BASE_URL`, with a real `EnrichedEvidence` built from the real
xordump alert through the actual `nodes.rag.rag_enrichment` (Stage 1→2)
chain, 2026-08-16. Wall-clock duration was 271.1s — confirms this
deployment's CPU-bound Stage 3 latency is materially higher than either
architecture doc's estimate, which is why `.env`'s `STAGE_3_LLM_TIMEOUT` is
set to 600s for this environment (see `nodes/context.py`'s module docstring
and REPO-STATUS.md). The fallback path was also deliberately triggered
live (pointing `config.LLM_BASE_URL` at an unreachable port) and confirmed
to produce a valid, non-crashing `ContextualAssessment` in 0.14s.

That original run's `correlation_decision.merge_into_case_id` was the
observed bug (an ID from Stage 2's `incident_matches`, not a real open
case — see CLAUDE.md "Observed Stage 3 output quality note"), fixed by the
schema-level enum constraint and post-parse validator below.
`tests/fixtures/context_live_run_fixed_real.json` is a SECOND real capture
— the exact same evidence, run through the actual fixed
`nodes.context.context_analysis` code path (not a mock), 2026-08-16,
confirming `merge_into_case_id` comes back `null` for real, not just under
test mocks. See `TestMergeFixVerifiedLive`.

Everything else here mocks `nodes.context._call_llm` or
`httpx.AsyncClient.post` directly and checks orchestration logic only:
JSON extraction, fallback routing, and prompt/schema construction.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

import config
from nodes import context as context_mod
from schemas import (
    CanonicalAlert,
    ContextualAssessment,
    EnrichedEvidence,
    EvidenceSituation,
    ExtractedObservable,
    ExtractedObservables,
    HashBundle,
    Host,
    Observables,
    Process,
    RawEvidence,
    Rule,
    RuleContext,
    ShallowCase,
    User,
)

FIXTURE = Path(__file__).parent / "fixtures" / "context_live_run_real.json"
FIXED_FIXTURE = Path(__file__).parent / "fixtures" / "context_live_run_fixed_real.json"
ESCAPING_BUG_FIXTURE = (
    Path(__file__).parent / "fixtures" / "context_stage3_vllm_escaping_bug_real.json"
)


@pytest.fixture(scope="module")
def real() -> dict:
    """REAL — one live nodes.context.context_analysis run, captured 2026-08-16
    (before the merge_into_case_id fix — see module docstring)."""
    return json.loads(FIXTURE.read_text())


@pytest.fixture(scope="module")
def real_fixed() -> dict:
    """REAL — the same evidence, live nodes.context.context_analysis run
    through the fixed code path, captured 2026-08-16."""
    return json.loads(FIXED_FIXTURE.read_text())


@pytest.fixture(scope="module")
def real_escaping_bug() -> dict:
    """REAL — the verbatim `message.content` from a live Stage 3 call against
    the Colab/vLLM backend (foundation-sec-reasoning, 8-bit bnb, T4),
    captured 2026-08-23 during the Ollama->vLLM backend-swap test. This is
    the exact response that exposed the JSON-escaping false-discard bug in
    _validate_extracted_observables: extracted_observables.process[0].value
    is "C:\\Windows\\Temp\\xordump.exe" (single backslash after JSON
    decoding) — the alert's genuine PowerShell -OutFile path — which the
    buggy substring check against evidence.model_dump_json() (JSON-escaped,
    double backslash) always discarded as a "hallucination". The other 5
    extracted_observables entries in this same real response (evil.com,
    192.168.1.1, a fabricated hash, etc.) are genuinely NOT in this alert's
    evidence and must remain correctly discarded by the fix."""
    return json.loads(ESCAPING_BUG_FIXTURE.read_text())


def run(coro):
    return asyncio.run(coro)


def make_evidence_situation(**overrides) -> EvidenceSituation:
    """v5 (`newdesign.md` §3) — ContextualAssessment.evidence_situation is
    required; this is the neutral default for tests that don't care about
    its content, only that ContextualAssessment validates."""
    defaults = dict(sources=[], overall_evidence_reliability="high", analyst_must_verify=[])
    defaults.update(overrides)
    return EvidenceSituation(**defaults)


# Same neutral default as make_evidence_situation(), as a plain dict — for
# raw JSON literals (json.dumps(...)) that stand in for an LLM response.
MIN_EVIDENCE_SITUATION_DICT = {
    "sources": [],
    "overall_evidence_reliability": "high",
    "analyst_must_verify": [],
}


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


def make_evidence(*, rule_context: RuleContext | None = None, open_cases=None) -> EnrichedEvidence:
    raw = RawEvidence(
        canonical_alert=make_alert(),
        rule_context=rule_context,
        open_cases=open_cases or [],
    )
    return EnrichedEvidence(**raw.model_dump())


def fake_response(content: str, status_code: int = 200) -> httpx.Response:
    request = httpx.Request("POST", "http://fake-ollama/v1/chat/completions")
    return httpx.Response(
        status_code,
        json={"choices": [{"message": {"content": content}}]},
        request=request,
    )


class TestHappyPath:
    def test_well_formed_response_parses_and_is_returned(self, monkeypatch):
        good_content = json.dumps(
            {
                "refined_mitre_mapping": [
                    {
                        "technique_id": "T1105",
                        "technique_name": "Ingress Tool Transfer",
                        "tactic": "command-and-control",
                        "confidence": "high",
                        "basis": "test",
                    }
                ],
                "correlation_decision": {
                    "action": "new",
                    "merge_into_case_id": None,
                    "kill_chain_progression_detected": False,
                    "reasoning": "test",
                },
                "additional_investigation_gaps": [],
                "evidence_situation": MIN_EVIDENCE_SITUATION_DICT,
            }
        )

        async def fake_post(self, url, *, headers, json, timeout):
            return fake_response(good_content)

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)

        evidence = make_evidence()
        assessment = run(context_mod.context_analysis(evidence))

        assert assessment.evidence_situation.overall_evidence_reliability == "high"
        assert assessment.refined_mitre_mapping[0].technique_id == "T1105"
        assert assessment.stage_3_duration_ms >= 0

    def test_request_uses_configured_model_and_json_schema_mode(self, monkeypatch):
        captured = {}

        async def fake_post(self, url, *, headers, json, timeout):
            captured["url"] = url
            captured["json"] = json
            captured["timeout"] = timeout
            return fake_response(
                '{"refined_mitre_mapping":[],"correlation_decision":{"action":"new",'
                '"merge_into_case_id":null,"kill_chain_progression_detected":false,'
                '"reasoning":"x"},'
                '"additional_investigation_gaps":[],'
                '"evidence_situation":{"sources":[],"overall_evidence_reliability":"low",'
                '"analyst_must_verify":[]}}'
            )

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
        run(context_mod.context_analysis(make_evidence()))

        assert captured["url"] == f"{config.LLM_BASE_URL}/chat/completions"
        assert captured["json"]["model"] == config.LLM_MODEL
        assert captured["json"]["response_format"]["type"] == "json_schema"
        assert captured["timeout"] == config.STAGE_3_LLM_TIMEOUT


class TestCappedMaxTokens:
    """2026-08-23 fix — regression guard for the live-caught bug: a real
    alert's prompt (4193 real tokens, confirmed by the backend's own 400
    error) plus the previous fixed max_tokens=4000 exceeded the model's
    8192-token context window. See config.py's LLM_MAX_CONTEXT_TOKENS/
    LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN/LLM_CONTEXT_SAFETY_MARGIN_TOKENS."""

    def test_small_prompt_gets_the_desired_value_unchanged(self):
        result = context_mod._capped_max_tokens("short system", "short user", desired=4000)
        assert result == 4000

    def test_large_prompt_gets_capped_below_desired(self, monkeypatch):
        # Pinned independent of .env: this deployment's Gemini test session
        # overrides LLM_MAX_CONTEXT_TOKENS to Gemini's real ~1M-token window
        # (see .env), under which a 5000-token prompt no longer forces a
        # cap. This test is about the capping MECHANISM, not which backend
        # is currently configured, so it fixes the window back to the
        # original 8192 it was written against.
        monkeypatch.setattr(config, "LLM_MAX_CONTEXT_TOKENS", 8192)
        # sized to estimate to ~5000 tokens -- big enough to force a cap
        # below the 4000 desired, small enough that the prompt alone still
        # leaves real headroom (unlike the pathological case in the next
        # test, where the prompt alone already exceeds the window and only
        # the floor can apply).
        large_user_prompt = "x" * int(5000 * config.LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN)
        result = context_mod._capped_max_tokens("short system", large_user_prompt, desired=4000)
        assert result < 4000

        estimated_prompt_tokens = len("short system" + large_user_prompt) / config.LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN
        assert estimated_prompt_tokens + result + config.LLM_CONTEXT_SAFETY_MARGIN_TOKENS <= config.LLM_MAX_CONTEXT_TOKENS

    def test_reproduces_the_live_caught_overflow_scenario(self, monkeypatch):
        """The exact real numbers from the live-caught bug: a ~4193-token
        prompt requesting max_tokens=4000 summed to 8193, one over the real
        8192-token window. The old fixed value would have failed; the capped
        value must not. Pinned to 8192 for the same reason as the test
        above — this reproduces a specific historical incident on the
        original deployment's window, independent of .env's current
        Gemini-session override."""
        monkeypatch.setattr(config, "LLM_MAX_CONTEXT_TOKENS", 8192)
        chars_for_4193_tokens = int(4193 * config.LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN)
        user_prompt = "x" * chars_for_4193_tokens
        result = context_mod._capped_max_tokens("", user_prompt, desired=4000)
        assert result < 4000
        assert 4193 + result <= config.LLM_MAX_CONTEXT_TOKENS

    def test_extreme_prompt_floors_at_the_minimum_rather_than_going_negative(self, monkeypatch):
        monkeypatch.setattr(config, "LLM_MAX_CONTEXT_TOKENS", 8192)
        enormous_prompt = "x" * 100_000
        result = context_mod._capped_max_tokens("", enormous_prompt, desired=4000)
        assert result == config.LLM_MIN_COMPLETION_TOKENS

    def test_reproduces_the_second_live_caught_calibration_gap(self):
        """The 3.5-chars/token default (this session's first fix) still
        underestimated once a real n8n payload bug was fixed and
        canonical_alert started carrying its real, GUID/hash-dense content:
        a real 19592-char prompt measured at 5799 real tokens (backend's own
        400 error) -- a 3.38 chars/token ratio, denser than 3.5 predicted.
        The old default + 200 margin landed at 5799+2394=8193, one over.
        Recalibrated to 3.2 chars/token + 400 margin; this exact real prompt
        must no longer be predicted to overflow."""
        real_chars = 19592
        real_tokens = 5799
        user_prompt = "x" * real_chars
        result = context_mod._capped_max_tokens("", user_prompt, desired=4000)
        assert real_tokens + result <= config.LLM_MAX_CONTEXT_TOKENS

    def test_call_llm_uses_configured_desired_value_not_a_hardcoded_literal(self, monkeypatch):
        """2026-08-23 — desired max_tokens moved from a bare literal (4000)
        to config.STAGE_3_DESIRED_MAX_TOKENS (raised via .env for the Gemini
        test session, since that model's real output limit is 65536 and it
        silently spends part of max_tokens on invisible 'thinking' tokens).
        Small prompt -> uncapped -> payload's max_tokens must equal whatever
        config says, proving _call_llm reads the config value live rather
        than a literal baked into the function."""
        monkeypatch.setattr(config, "STAGE_3_DESIRED_MAX_TOKENS", 7777)
        captured = {}

        async def fake_post(self, url, *, headers, json, timeout):
            captured["json"] = json
            return fake_response(
                '{"refined_mitre_mapping":[],"correlation_decision":{"action":"new",'
                '"merge_into_case_id":null,"kill_chain_progression_detected":false,'
                '"reasoning":"x"},'
                '"additional_investigation_gaps":[],'
                '"evidence_situation":{"sources":[],"overall_evidence_reliability":"low",'
                '"analyst_must_verify":[]}}'
            )

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
        evidence = make_evidence(rule_context=RuleContext(found=True, description="short"))
        run(context_mod.context_analysis(evidence))

        assert captured["json"]["max_tokens"] == 7777

    def test_payload_max_tokens_reflects_the_cap(self, monkeypatch):
        """End-to-end: a real oversized evidence object must produce a
        request whose max_tokens is actually capped, not just the standalone
        helper function in isolation. Window pinned to 8192 (see the two
        tests above) so this holds regardless of .env's current backend."""
        monkeypatch.setattr(config, "LLM_MAX_CONTEXT_TOKENS", 8192)
        captured = {}

        async def fake_post(self, url, *, headers, json, timeout):
            captured["json"] = json
            return fake_response(
                '{"refined_mitre_mapping":[],"correlation_decision":{"action":"new",'
                '"merge_into_case_id":null,"kill_chain_progression_detected":false,'
                '"reasoning":"x"},'
                '"additional_investigation_gaps":[],'
                '"evidence_situation":{"sources":[],"overall_evidence_reliability":"low",'
                '"analyst_must_verify":[]}}'
            )

        monkeypatch.setattr(httpx.AsyncClient, "post", fake_post)
        evidence = make_evidence(
            rule_context=RuleContext(found=True, description="x" * 30_000)
        )
        run(context_mod.context_analysis(evidence))

        assert captured["json"]["max_tokens"] < config.STAGE_3_DESIRED_MAX_TOKENS


class TestSelfContinuationIsHandled:
    """Reproduces the actual shape observed live under plain json_object
    mode: a valid JSON object followed by hallucinated extra prose/JSON
    turns. json_schema mode didn't reproduce this in testing, but the
    extraction stays defensive regardless — see nodes/context.py."""

    def test_extracts_only_the_first_json_object(self):
        content = (
            '{"confidence":"low","note":"ok"}\n\n'
            "Would you like another?yes\n\n"
            'A user was found accessing something.\n\n{"confidence":"medium","note":"other"}'
        )
        parsed = context_mod._extract_first_json_object(content)
        assert parsed == {"confidence": "low", "note": "ok"}

    def test_handles_leading_and_trailing_whitespace(self):
        content = '  \n  {"confidence":"high","note":"ok"}  \n  trailing garbage'
        parsed = context_mod._extract_first_json_object(content)
        assert parsed == {"confidence": "high", "note": "ok"}


class TestFallbackPaths:
    """Every failure class funnels to the same deterministic fallback —
    never an unhandled exception reaching context_analysis's caller."""

    def test_connection_error(self, monkeypatch):
        async def raising_call_llm(evidence):
            raise httpx.ConnectError("simulated: connection refused")

        monkeypatch.setattr(context_mod, "_call_llm", raising_call_llm)
        assessment = run(context_mod.context_analysis(make_evidence()))
        assert assessment.evidence_situation.overall_evidence_reliability == "low"

    def test_read_timeout(self, monkeypatch):
        async def raising_call_llm(evidence):
            raise httpx.ReadTimeout("simulated: timed out")

        monkeypatch.setattr(context_mod, "_call_llm", raising_call_llm)
        assessment = run(context_mod.context_analysis(make_evidence()))
        assert assessment.evidence_situation.overall_evidence_reliability == "low"

    def test_non_2xx_status(self, monkeypatch):
        async def raising_call_llm(evidence):
            request = httpx.Request("POST", "http://fake")
            response = httpx.Response(500, request=request)
            raise httpx.HTTPStatusError("simulated 500", request=request, response=response)

        monkeypatch.setattr(context_mod, "_call_llm", raising_call_llm)
        assessment = run(context_mod.context_analysis(make_evidence()))
        assert assessment.evidence_situation.overall_evidence_reliability == "low"

    def test_malformed_json_body(self, monkeypatch):
        async def bad_call_llm(evidence):
            return "this is not json at all"

        monkeypatch.setattr(context_mod, "_call_llm", bad_call_llm)
        assessment = run(context_mod.context_analysis(make_evidence()))
        assert assessment.evidence_situation.overall_evidence_reliability == "low"

    def test_json_fails_pydantic_validation(self, monkeypatch):
        async def bad_call_llm(evidence):
            return json.dumps({"evidence_situation": "not an object", "not_a_real_field": True})

        monkeypatch.setattr(context_mod, "_call_llm", bad_call_llm)
        assessment = run(context_mod.context_analysis(make_evidence()))
        assert assessment.evidence_situation.overall_evidence_reliability == "low"


class TestFallbackPreservesRuleContextMitre:
    def test_both_techniques_survive_into_fallback(self, monkeypatch):
        """Regression guard for the v3 silent-severity-cap bug architecture
        §8 calls out by name: the fallback must never discard Stage 1's
        rule-derived MITRE mapping."""

        async def raising_call_llm(evidence):
            raise httpx.ConnectError("simulated")

        monkeypatch.setattr(context_mod, "_call_llm", raising_call_llm)

        rule_context = RuleContext(found=True, mitre_attack=["T1105", "T1059.001"])
        evidence = make_evidence(rule_context=rule_context)
        assessment = run(context_mod.context_analysis(evidence))

        technique_ids = {m.technique_id for m in assessment.refined_mitre_mapping}
        assert technique_ids == {"T1105", "T1059.001"}
        assert all(m.confidence == "medium" for m in assessment.refined_mitre_mapping)

    def test_open_case_drives_merge_decision_in_fallback(self, monkeypatch):
        async def raising_call_llm(evidence):
            raise httpx.ConnectError("simulated")

        monkeypatch.setattr(context_mod, "_call_llm", raising_call_llm)

        case = ShallowCase(case_id="~999", title="prior case")
        evidence = make_evidence(open_cases=[case])
        assessment = run(context_mod.context_analysis(evidence))

        assert assessment.correlation_decision.action == "merge"
        assert assessment.correlation_decision.merge_into_case_id == "~999"


class TestFallbackWithNoRuleContext:
    def test_none_rule_context_does_not_raise(self, monkeypatch):
        async def raising_call_llm(evidence):
            raise httpx.ConnectError("simulated")

        monkeypatch.setattr(context_mod, "_call_llm", raising_call_llm)

        evidence = make_evidence(rule_context=None)
        assessment = run(context_mod.context_analysis(evidence))

        assert assessment.refined_mitre_mapping == []
        assert assessment.evidence_situation.overall_evidence_reliability == "low"


class TestSchemaStaysInSync:
    def test_hand_inlined_schema_matches_pydantic_model_fields(self):
        """Guards against prompts.context_agent.CONTEXTUAL_ASSESSMENT_SCHEMA
        silently drifting from ContextualAssessment after a future field
        change — see prompts/context_agent.py's module docstring for why
        it's hand-inlined instead of derived directly.

        Only field NAMES are compared, not the "required" set: the two
        schemas serve different jobs on purpose. The hand-schema is an
        LLM-facing output contract and deliberately requires all 5
        top-level fields (the model should never omit one). The Pydantic
        model is the Python-facing input contract and deliberately allows
        defaults on 4 of them (only `correlation_decision` is required),
        because the deterministic fallback and defensive parsing both need
        to construct a valid ContextualAssessment from partial data. A
        field being present in one schema but missing from the other is
        the real drift this test should catch — the two "required" sets
        disagreeing is not."""
        import prompts.context_agent as ctx_prompts

        pydantic_schema = ContextualAssessment.model_json_schema()
        defs = pydantic_schema.get("$defs", {})

        hand_schema = ctx_prompts.build_contextual_assessment_schema(make_evidence())

        # stage_3_duration_ms is set by nodes/context.py AFTER the LLM call
        # returns (time.monotonic() delta) — it must never be a field the
        # LLM is asked to fill in, so it's deliberately absent from the
        # LLM-facing schema.
        llm_facing_fields = set(pydantic_schema["properties"].keys()) - {"stage_3_duration_ms"}
        assert llm_facing_fields == set(hand_schema["properties"].keys())

        # spot-check one nested model's field NAMES agree too
        mitre_mapping_def = defs["MitreMapping"]
        hand_mitre_item = hand_schema["properties"]["refined_mitre_mapping"]["items"]
        assert set(mitre_mapping_def["properties"].keys()) == set(
            hand_mitre_item["properties"].keys()
        )

        # same spot-check for ExtractedObservable — the 2026-08-16 addition
        extracted_observable_def = defs["ExtractedObservable"]
        hand_process_item = hand_schema["properties"]["extracted_observables"]["properties"][
            "process"
        ]["items"]
        assert set(extracted_observable_def["properties"].keys()) == set(
            hand_process_item["properties"].keys()
        )

        # ExtractedObservables' own bucket names (process/file/external_ips/
        # domains/urls/hash) must agree between the two schemas too
        extracted_observables_def = defs["ExtractedObservables"]
        hand_extracted_observables = hand_schema["properties"]["extracted_observables"]
        assert set(extracted_observables_def["properties"].keys()) == set(
            hand_extracted_observables["properties"].keys()
        )


class TestDynamicMergeSchema:
    """Regression guard for the observed live bug: the LLM once set
    merge_into_case_id to an incident_matches ID when open_cases was empty.
    Fixed by constraining the schema's enum to this alert's real open
    cases — see prompts/context_agent.py's module docstring."""

    def test_no_open_cases_forces_null_only(self):
        import prompts.context_agent as ctx_prompts

        schema = ctx_prompts.build_contextual_assessment_schema(make_evidence(open_cases=[]))
        correlation = schema["properties"]["correlation_decision"]["properties"]

        assert correlation["merge_into_case_id"]["enum"] == [None]
        assert correlation["action"]["enum"] == ["new"]

    def test_open_cases_present_constrains_enum_to_real_ids(self):
        import prompts.context_agent as ctx_prompts

        cases = [ShallowCase(case_id="~1"), ShallowCase(case_id="~2")]
        schema = ctx_prompts.build_contextual_assessment_schema(make_evidence(open_cases=cases))
        correlation = schema["properties"]["correlation_decision"]["properties"]

        assert correlation["merge_into_case_id"]["enum"] == ["~1", "~2", None]
        assert correlation["action"]["enum"] == ["new", "merge"]

    def test_base_schema_template_is_never_mutated(self):
        """build_contextual_assessment_schema must deep-copy — two calls
        with different evidence must not leak enum values into each other
        via a shared mutable dict."""
        import prompts.context_agent as ctx_prompts

        ctx_prompts.build_contextual_assessment_schema(
            make_evidence(open_cases=[ShallowCase(case_id="~contaminated")])
        )
        fresh = ctx_prompts.build_contextual_assessment_schema(make_evidence(open_cases=[]))
        correlation = fresh["properties"]["correlation_decision"]["properties"]
        assert correlation["merge_into_case_id"]["enum"] == [None]


class TestMergeTargetValidation:
    """Defense-in-depth behind the schema constraint — exercises
    nodes.context._validate_merge_target directly, bypassing schema
    enforcement entirely to prove the safety net holds independently of it."""

    def test_valid_merge_target_is_kept(self):
        good_content = json.dumps(
            {
                "refined_mitre_mapping": [],
                "correlation_decision": {
                    "action": "merge",
                    "merge_into_case_id": "~999",
                    "kill_chain_progression_detected": False,
                    "reasoning": "test",
                },
                "additional_investigation_gaps": [],
                "evidence_situation": MIN_EVIDENCE_SITUATION_DICT,
            }
        )
        assessment = ContextualAssessment.model_validate(json.loads(good_content))
        evidence = make_evidence(open_cases=[ShallowCase(case_id="~999")])

        result = context_mod._validate_merge_target(assessment, evidence)

        assert result.correlation_decision.merge_into_case_id == "~999"
        assert result.additional_investigation_gaps == []

    def test_invalid_merge_target_is_discarded_with_a_gap_note(self):
        """Reproduces the original bug shape directly: a merge_into_case_id
        that doesn't correspond to any real open case (as if it had leaked
        in from incident_matches) — bypasses the schema enum entirely to
        prove this safety net works on its own."""
        assessment = ContextualAssessment(
            correlation_decision=context_mod.CorrelationDecision(
                action="merge",
                merge_into_case_id="~8613944",  # not a real open case
                kill_chain_progression_detected=False,
                reasoning="test",
            ),
            evidence_situation=make_evidence_situation(),
        )
        evidence = make_evidence(open_cases=[])  # no open cases at all

        result = context_mod._validate_merge_target(assessment, evidence)

        assert result.correlation_decision.merge_into_case_id is None
        assert len(result.additional_investigation_gaps) == 1
        assert "~8613944" in result.additional_investigation_gaps[0]

    def test_none_merge_target_is_a_no_op(self):
        assessment = ContextualAssessment(
            correlation_decision=context_mod.CorrelationDecision(
                action="new",
                merge_into_case_id=None,
                kill_chain_progression_detected=False,
                reasoning="test",
            ),
            evidence_situation=make_evidence_situation(),
        )
        evidence = make_evidence(open_cases=[])

        result = context_mod._validate_merge_target(assessment, evidence)

        assert result.correlation_decision.merge_into_case_id is None
        assert result.additional_investigation_gaps == []

    def test_end_to_end_through_context_analysis(self, monkeypatch):
        """The full path: a mocked LLM response proposing a bogus merge
        target gets cleaned up by context_analysis before it's returned,
        not just by calling _validate_merge_target directly."""
        bad_content = json.dumps(
            {
                "refined_mitre_mapping": [],
                "correlation_decision": {
                    "action": "merge",
                    "merge_into_case_id": "~8613944",
                    "kill_chain_progression_detected": False,
                    "reasoning": "test",
                },
                "additional_investigation_gaps": [],
                "evidence_situation": MIN_EVIDENCE_SITUATION_DICT,
            }
        )

        async def fake_call_llm(evidence):
            return bad_content

        monkeypatch.setattr(context_mod, "_call_llm", fake_call_llm)
        evidence = make_evidence(open_cases=[])

        assessment = run(context_mod.context_analysis(evidence))

        assert assessment.correlation_decision.merge_into_case_id is None
        assert any("~8613944" in gap for gap in assessment.additional_investigation_gaps)


class TestUserPromptIsFullEvidenceNoTruncation:
    def test_prompt_round_trips_and_contains_deep_field(self):
        import prompts.context_agent as ctx_prompts

        evidence = make_evidence(rule_context=RuleContext(found=True, title="A Rule"))
        prompt = ctx_prompts.build_user_prompt(evidence)

        parsed = json.loads(prompt)
        assert parsed["rule_context"]["title"] == "A Rule"
        assert parsed["canonical_alert"]["rule"]["uuid"] == "5e3cc4d8-…"


class TestRealFixtureLooksReasonable:
    """Sanity checks on the captured real live run — not a mock, reads
    tests/fixtures/context_live_run_real.json directly."""

    @pytest.mark.skip(
        reason="context_live_run_real.json predates the v5 redesign (newdesign.md) — "
        "it carries the now-removed contextual_modifiers/confidence/llm_criticality_score "
        "and lacks the now-required evidence_situation, so it can no longer validate "
        "against the current ContextualAssessment. Needs a fresh live Stage 3 capture "
        "under the v5 prompt/schema (newdesign.md §11 step 5) to re-enable."
    )
    def test_parsed_assessment_validates_against_the_real_schema(self, real):
        ContextualAssessment.model_validate(real["parsed_assessment"])

    def test_mitre_mapping_is_relevant_to_the_real_alert(self, real):
        technique_ids = {m["technique_id"] for m in real["parsed_assessment"]["refined_mitre_mapping"]}
        assert "T1059.001" in technique_ids

    def test_user_prompt_contains_no_placeholder_literals(self, real):
        assert "{field}" not in real["user_prompt"]
        assert "{evidence}" not in real["user_prompt"]


class TestExtractedObservablesSchema:
    """extracted_observables mirrors schemas.alert.Observables' type split
    (external_ips/domains/urls as separate lists) plus process/file/hash
    buckets with no Observables equivalent — see CLAUDE.md's 2026-08-16
    entry and prompts/context_agent.py's module docstring."""

    def test_all_six_buckets_present_in_hand_schema(self):
        import prompts.context_agent as ctx_prompts

        schema = ctx_prompts.build_contextual_assessment_schema(make_evidence())
        buckets = schema["properties"]["extracted_observables"]["properties"].keys()
        assert set(buckets) == {"process", "file", "external_ips", "domains", "urls", "hash"}

    def test_each_bucket_constrains_observable_type_to_a_single_matching_value(self):
        """Live-verified regression guard (2026-08-16): with a shared 6-way
        enum across all buckets, the LLM filled every bucket with a
        mismatched type (process bucket -> "file", hash bucket -> "file",
        domains bucket -> "url", etc.) — nothing structurally tied a
        bucket's name to its items' observable_type. Fixed by constraining
        each bucket's enum to exactly the one type it should hold."""
        import prompts.context_agent as ctx_prompts

        schema = ctx_prompts.build_contextual_assessment_schema(make_evidence())
        buckets = schema["properties"]["extracted_observables"]["properties"]

        expected = {
            "process": "process-path",
            "file": "file",
            "external_ips": "ip",
            "domains": "domain",
            "urls": "url",
            "hash": "hash",
        }
        for bucket_name, expected_type in expected.items():
            enum = buckets[bucket_name]["items"]["properties"]["observable_type"]["enum"]
            assert enum == [expected_type], f"{bucket_name} bucket allows {enum}"

    def test_valid_extraction_parses_into_the_pydantic_model(self):
        assessment = ContextualAssessment.model_validate(
            {
                "correlation_decision": {
                    "action": "new",
                    "merge_into_case_id": None,
                    "kill_chain_progression_detected": False,
                    "reasoning": "test",
                },
                "extracted_observables": {
                    "file": [
                        {
                            "observable_type": "file",
                            "value": "C:\\Windows\\Temp\\xordump.exe",
                            "rationale": "downloaded to suspicious temp path",
                            "confidence": "high",
                            "source": "behavioral_analysis",
                        }
                    ]
                },
                "evidence_situation": MIN_EVIDENCE_SITUATION_DICT,
            }
        )
        assert assessment.extracted_observables.file[0].value == "C:\\Windows\\Temp\\xordump.exe"
        assert assessment.extracted_observables.process == []

    def test_unknown_observable_type_is_rejected(self):
        with pytest.raises(Exception):
            ContextualAssessment.model_validate(
                {
                    "correlation_decision": {
                        "action": "new",
                        "merge_into_case_id": None,
                        "kill_chain_progression_detected": False,
                        "reasoning": "test",
                    },
                    "extracted_observables": {
                        "file": [
                            {
                                "observable_type": "registry_key",  # not in the Literal enum
                                "value": "HKLM\\...",
                                "rationale": "x",
                                "confidence": "high",
                                "source": "behavioral_analysis",
                            }
                        ]
                    },
                }
            )


class TestExtractedObservablesValidation:
    """Defense-in-depth behind the prompt's evidence-grounding instruction
    and per-bucket schema enum — exercises
    nodes.context._validate_extracted_observables directly, bypassing
    schema/prompt compliance entirely to prove the safety net holds on its
    own. Regression guard for the two live-observed failure modes from the
    2026-08-16 extended run: fabricated values with no basis in the
    evidence, and re-extracting an IOC n8n's extractor already captured."""

    def test_value_traceable_to_evidence_is_kept(self):
        evidence = make_evidence()
        # host.hostname="win-kvkmd51ggkq" is set by make_alert's defaults,
        # so it genuinely appears in evidence.model_dump_json().
        assessment = ContextualAssessment(
            correlation_decision=context_mod.CorrelationDecision(
                action="new", kill_chain_progression_detected=False, reasoning="x"
            ),
            extracted_observables=ExtractedObservables(
                process=[
                    ExtractedObservable(
                        observable_type="process-path",
                        value="win-kvkmd51ggkq",
                        rationale="present in evidence",
                        confidence="high",
                        source="behavioral_analysis",
                    )
                ]
            ),
            evidence_situation=make_evidence_situation(),
        )
        result = context_mod._validate_extracted_observables(assessment, evidence)
        assert len(result.extracted_observables.process) == 1
        assert result.additional_investigation_gaps == []

    def test_fabricated_value_is_discarded_with_a_gap_note(self):
        """Reproduces the live-observed hallucination directly: a hash that
        doesn't appear anywhere in the evidence at all."""
        evidence = make_evidence()
        assessment = ContextualAssessment(
            correlation_decision=context_mod.CorrelationDecision(
                action="new", kill_chain_progression_detected=False, reasoning="x"
            ),
            extracted_observables=ExtractedObservables(
                hash=[
                    ExtractedObservable(
                        observable_type="hash",
                        value="a1b2c3d4e5f6g7h8i9j0k",  # not real, invented
                        rationale="looked plausible",
                        confidence="high",
                        source="command_line_parsing",
                    )
                ]
            ),
            evidence_situation=make_evidence_situation(),
        )
        result = context_mod._validate_extracted_observables(assessment, evidence)
        assert result.extracted_observables.hash == []
        assert len(result.additional_investigation_gaps) == 1
        assert "a1b2c3d4e5f6g7h8i9j0k" in result.additional_investigation_gaps[0]

    def test_value_duplicating_canonical_observables_is_silently_dropped(self):
        """A real value that's traceable to the evidence but already present
        in canonical_alert.observables isn't new information — dropped, but
        without a gap note (it's not an error, just redundant)."""
        alert = make_alert(
            observables=Observables(
                external_ips=["1.2.3.4"], hashes=HashBundle(sha256=["deadbeef" * 8])
            )
        )
        raw = RawEvidence(canonical_alert=alert)
        evidence = EnrichedEvidence(**raw.model_dump())

        assessment = ContextualAssessment(
            correlation_decision=context_mod.CorrelationDecision(
                action="new", kill_chain_progression_detected=False, reasoning="x"
            ),
            extracted_observables=ExtractedObservables(
                external_ips=[
                    ExtractedObservable(
                        observable_type="ip",
                        value="1.2.3.4",
                        rationale="re-derived",
                        confidence="high",
                        source="behavioral_analysis",
                    )
                ]
            ),
            evidence_situation=make_evidence_situation(),
        )
        result = context_mod._validate_extracted_observables(assessment, evidence)
        assert result.extracted_observables.external_ips == []
        assert result.additional_investigation_gaps == []

    def test_backslash_value_traceable_to_evidence_is_kept(self):
        """Regression guard for the 2026-08-23 vLLM live run: a Windows path
        (a backslash-bearing value) that genuinely appears in evidence must
        be kept, not discarded — see CLAUDE.md's escaping-bug writeup and
        nodes/context.py's comment at the fix site."""
        alert = make_alert(
            process=Process(command_line="powershell -OutFile C:\\Windows\\Temp\\xordump.exe")
        )
        evidence = EnrichedEvidence(**RawEvidence(canonical_alert=alert).model_dump())
        assessment = ContextualAssessment(
            correlation_decision=context_mod.CorrelationDecision(
                action="new", kill_chain_progression_detected=False, reasoning="x"
            ),
            extracted_observables=ExtractedObservables(
                process=[
                    ExtractedObservable(
                        observable_type="process-path",
                        value="C:\\Windows\\Temp\\xordump.exe",
                        rationale="present in evidence",
                        confidence="high",
                        source="behavioral_analysis",
                    )
                ]
            ),
            evidence_situation=make_evidence_situation(),
        )
        result = context_mod._validate_extracted_observables(assessment, evidence)
        assert len(result.extracted_observables.process) == 1
        assert result.additional_investigation_gaps == []

    def test_double_quote_value_traceable_to_evidence_is_kept(self):
        """Same escaping class as the backslash bug, for the other JSON
        special character the naive substring check mishandled."""
        alert = make_alert(process=Process(command_line='cmd /c echo "flagged" > out.txt'))
        evidence = EnrichedEvidence(**RawEvidence(canonical_alert=alert).model_dump())
        assessment = ContextualAssessment(
            correlation_decision=context_mod.CorrelationDecision(
                action="new", kill_chain_progression_detected=False, reasoning="x"
            ),
            extracted_observables=ExtractedObservables(
                file=[
                    ExtractedObservable(
                        observable_type="file",
                        value='echo "flagged" > out.txt',
                        rationale="present in evidence",
                        confidence="high",
                        source="behavioral_analysis",
                    )
                ]
            ),
            evidence_situation=make_evidence_situation(),
        )
        result = context_mod._validate_extracted_observables(assessment, evidence)
        assert len(result.extracted_observables.file) == 1
        assert result.additional_investigation_gaps == []

    def test_non_ascii_value_traceable_to_evidence_is_kept(self):
        """Guards the ensure_ascii=False requirement: Pydantic's
        model_dump_json() emits raw UTF-8, not \\uXXXX escapes, so the fix's
        escaped needle must match that (an IDN domain, a non-ASCII
        username-in-path, etc.)."""
        alert = make_alert(process=Process(command_line="whoami /user café-admin"))
        evidence = EnrichedEvidence(**RawEvidence(canonical_alert=alert).model_dump())
        assessment = ContextualAssessment(
            correlation_decision=context_mod.CorrelationDecision(
                action="new", kill_chain_progression_detected=False, reasoning="x"
            ),
            extracted_observables=ExtractedObservables(
                process=[
                    ExtractedObservable(
                        observable_type="process-path",
                        value="café-admin",
                        rationale="present in evidence",
                        confidence="high",
                        source="behavioral_analysis",
                    )
                ]
            ),
            evidence_situation=make_evidence_situation(),
        )
        result = context_mod._validate_extracted_observables(assessment, evidence)
        assert len(result.extracted_observables.process) == 1
        assert result.additional_investigation_gaps == []

    def test_backslash_value_not_in_evidence_is_still_discarded(self):
        """Negative control: the fix must not degrade into "always keep" —
        a backslash-bearing value that is genuinely absent from evidence
        still gets caught as a hallucination."""
        evidence = make_evidence()
        assessment = ContextualAssessment(
            correlation_decision=context_mod.CorrelationDecision(
                action="new", kill_chain_progression_detected=False, reasoning="x"
            ),
            extracted_observables=ExtractedObservables(
                process=[
                    ExtractedObservable(
                        observable_type="process-path",
                        value="C:\\totally\\made\\up.exe",
                        rationale="fabricated",
                        confidence="high",
                        source="behavioral_analysis",
                    )
                ]
            ),
            evidence_situation=make_evidence_situation(),
        )
        result = context_mod._validate_extracted_observables(assessment, evidence)
        assert result.extracted_observables.process == []
        assert len(result.additional_investigation_gaps) == 1
        # the gap note embeds item.value via !r (Python repr, which doubles
        # backslashes for display) — matching repr() output here, not the
        # raw value, so this assertion isn't itself confused by the same
        # escaping distinction the fix is about.
        assert repr("C:\\totally\\made\\up.exe") in result.additional_investigation_gaps[0]

    def test_escaping_fix_verified_against_real_vllm_capture(self, monkeypatch, real_escaping_bug):
        """The exact real bug, reproduced end-to-end through
        context_analysis using this session's own live-captured vLLM
        response (see the `real_escaping_bug` fixture docstring): the real
        process-path value must now be kept, and the 5 genuinely-fabricated
        values from that same real response must still be discarded.

        v5 schema patch: `real_escaping_bug["content"]` was captured before
        the v5 redesign (`newdesign.md`) — it carries the now-removed
        `contextual_modifiers`/`confidence`/`llm_criticality_score` fields
        and lacks the now-required `evidence_situation`. The real
        `extracted_observables` values under test (the genuine xordump path,
        the 5 genuinely-fabricated values) are used byte-for-byte,
        unmodified — only the enclosing envelope is patched to satisfy the
        current schema, since replaying this exact real response through the
        current code path needs no less. A fresh live capture under the v5
        prompt/schema is still the real follow-up per this repo's fixture
        discipline (`newdesign.md` §11 step 5) — not a substitute for it."""

        patched_content = json.loads(real_escaping_bug["content"])
        for legacy_field in ("contextual_modifiers", "confidence", "llm_criticality_score"):
            patched_content.pop(legacy_field, None)
        patched_content["evidence_situation"] = MIN_EVIDENCE_SITUATION_DICT

        async def fake_call_llm(evidence):
            return json.dumps(patched_content)

        monkeypatch.setattr(context_mod, "_call_llm", fake_call_llm)

        alert = make_alert(
            process=Process(
                command_line=(
                    "powershell.exe & {[Net.ServicePointManager]::SecurityProtocol = "
                    "[Net.SecurityProtocolType]::Tls12\nInvoke-WebRequest "
                    '"https://github.com/audibleblink/xordump/releases/download/v0.0.1/xordump.exe" '
                    "-OutFile C:\\Windows\\Temp\\xordump.exe}"
                )
            )
        )
        evidence = EnrichedEvidence(**RawEvidence(canonical_alert=alert).model_dump())

        assessment = run(context_mod.context_analysis(evidence))

        kept_process_values = [item.value for item in assessment.extracted_observables.process]
        assert "C:\\Windows\\Temp\\xordump.exe" in kept_process_values

        assert assessment.extracted_observables.file == []
        assert assessment.extracted_observables.external_ips == []
        assert assessment.extracted_observables.domains == []
        assert assessment.extracted_observables.urls == []
        assert assessment.extracted_observables.hash == []
        assert len(assessment.additional_investigation_gaps) == 5

    def test_end_to_end_through_context_analysis(self, monkeypatch):
        """The full path: a mocked LLM response with a hallucinated hash
        gets cleaned up by context_analysis before it's returned."""
        bad_content = json.dumps(
            {
                "refined_mitre_mapping": [],
                "correlation_decision": {
                    "action": "new",
                    "merge_into_case_id": None,
                    "kill_chain_progression_detected": False,
                    "reasoning": "test",
                },
                "additional_investigation_gaps": [],
                "extracted_observables": {
                    "hash": [
                        {
                            "observable_type": "hash",
                            "value": "not-in-evidence-at-all",
                            "rationale": "x",
                            "confidence": "high",
                            "source": "command_line_parsing",
                        }
                    ]
                },
                "evidence_situation": MIN_EVIDENCE_SITUATION_DICT,
            }
        )

        async def fake_call_llm(evidence):
            return bad_content

        monkeypatch.setattr(context_mod, "_call_llm", fake_call_llm)
        evidence = make_evidence()

        assessment = run(context_mod.context_analysis(evidence))

        assert assessment.extracted_observables.hash == []
        assert any(
            "not-in-evidence-at-all" in gap for gap in assessment.additional_investigation_gaps
        )


class TestFallbackSetsSafeExtractionDefaults:
    """A downed LLM must never fabricate an IOC — the fallback's
    extracted_observables stays empty. (v5, `newdesign.md`: the old
    llm_criticality_score neutral-midpoint tests that used to live here are
    gone along with the field itself — see TestFallbackBuildsEvidenceSituation
    below for the fallback's new evidence_situation coverage.)"""

    def test_fallback_extracted_observables_are_all_empty(self, monkeypatch):
        async def raising_call_llm(evidence):
            raise httpx.ConnectError("simulated")

        monkeypatch.setattr(context_mod, "_call_llm", raising_call_llm)
        assessment = run(context_mod.context_analysis(make_evidence()))

        obs = assessment.extracted_observables
        assert obs.process == []
        assert obs.file == []
        assert obs.external_ips == []
        assert obs.domains == []
        assert obs.urls == []
        assert obs.hash == []


class TestSystemPromptCoversNewInstructions:
    """Cortex-verdict filtering is entirely prompt-driven (no code-level
    Cortex parsing exists). Evidence-grounding and n8n-observable dedup are
    prompt-driven AND code-enforced (nodes.context._validate_extracted_
    observables, see TestExtractedObservablesValidation) — belt-and-
    suspenders, matching this repo's merge_into_case_id precedent. These
    checks guard the prompt instructions themselves don't silently regress."""

    def test_prompt_explains_cortex_verdict_is_pre_filtered(self):
        import prompts.context_agent as ctx_prompts

        assert "malicious" in ctx_prompts.SYSTEM_PROMPT
        assert "suspicious" in ctx_prompts.SYSTEM_PROMPT
        assert "info" in ctx_prompts.SYSTEM_PROMPT

    def test_prompt_instructs_against_duplicating_n8n_observables(self):
        import prompts.context_agent as ctx_prompts

        assert "canonical_alert.observables" in ctx_prompts.SYSTEM_PROMPT

    def test_prompt_defines_evidence_source_statuses(self):
        """v5 (`newdesign.md` §3) replaces the old 0-100 criticality score
        range check — TASK 5 now defines the present/empty/missing
        vocabulary instead."""
        import prompts.context_agent as ctx_prompts

        assert '"present"' in ctx_prompts.SYSTEM_PROMPT
        assert '"empty"' in ctx_prompts.SYSTEM_PROMPT
        assert '"missing"' in ctx_prompts.SYSTEM_PROMPT

    def test_prompt_requires_values_copied_verbatim_from_evidence(self):
        """Live-verified regression guard (2026-08-16): without this
        instruction, the model fabricated a hash, an IP, and a rewritten
        command line with no basis in the real evidence. Enforced in code
        too — see TestExtractedObservablesValidation — but the prompt
        instruction is the first line of defense."""
        import prompts.context_agent as ctx_prompts

        assert "copied character-for-character" in ctx_prompts.SYSTEM_PROMPT
        assert "hallucination" in ctx_prompts.SYSTEM_PROMPT

    def test_prompt_distinguishes_missing_from_empty(self):
        """v5 (`newdesign.md` §3) replaces the old contextual_modifiers/
        criticality-score reconciliation check — the load-bearing
        distinction TASK 5 draws now is missing vs. empty evidence."""
        import prompts.context_agent as ctx_prompts

        assert 'Never treat "missing" and "empty" as the same thing' in ctx_prompts.SYSTEM_PROMPT

    def test_prompt_names_extraction_and_scoring_as_explicit_tasks(self):
        import prompts.context_agent as ctx_prompts

        assert "TASK 4" in ctx_prompts.SYSTEM_PROMPT
        assert "TASK 5" in ctx_prompts.SYSTEM_PROMPT


class TestMergeFixVerifiedLive:
    """Reads tests/fixtures/context_live_run_fixed_real.json — a real,
    unmocked re-run of the exact evidence that originally produced the bug,
    through the actual fixed code path. Proves the fix live, not just that
    the mocked unit tests above pass."""

    def test_merge_into_case_id_is_null_not_a_rag_match(self, real_fixed):
        assert real_fixed["parsed_assessment"]["correlation_decision"]["merge_into_case_id"] is None

    def test_action_is_new_not_merge(self, real_fixed):
        assert real_fixed["parsed_assessment"]["correlation_decision"]["action"] == "new"

    def test_schema_enum_was_actually_constrained_for_this_call(self, real_fixed):
        assert real_fixed["merge_into_case_id_schema_enum"] == [None]
        assert real_fixed["action_schema_enum"] == ["new"]

    def test_analysis_quality_did_not_degrade(self, real_fixed):
        """The fix shouldn't come at the cost of a worse analysis — still
        expect a relevant MITRE technique for this PowerShell alert."""
        technique_ids = {
            m["technique_id"]
            for m in real_fixed["parsed_assessment"]["refined_mitre_mapping"]
        }
        assert "T1059.001" in technique_ids
