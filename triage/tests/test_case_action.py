"""`tools/thehive.py`'s write functions and `nodes/case_action.py` — the
case-creation/merge stage, a deliberate 2026-08-21 deviation from
architecture §1/§3's read-only design (see CLAUDE.md's "Case action" entry
and both modules' docstrings for the full record).

PROVENANCE, all real, all 2026-08-21, against the live TheHive instance:

- `update_case` and `add_case_comment` were each called for real against the
  disposable test case `~8609848` (a manually-created "test" case with zero
  real observables — already the safe target this repo's own `thehive_real
  .json` fixture documents) and confirmed to work (`204`/`201`).
- `create_case_from_alert`'s underlying `POST /api/v1/alert/{id}/case`
  endpoint was discovered and confirmed live (real case `~4464672` created
  from real alert `~4636880`, 201) — but the composed FUNCTION itself
  (promote, then PATCH content) could not be run as one unbroken real call:
  this deployment had exactly 3 real alerts total, and both spare ones were
  consumed by endpoint discovery before the function was written. The two
  halves are each independently real-verified (create via raw probe, PATCH
  via `update_case`'s real success above); the composition is not. Documented
  here rather than silently claimed as fully tested.
- `merge_alert_into_case` was verified live TWICE: once directly (a real
  already-imported alert merged toward the test case, real HTTP 400 "Alert
  is already imported" — confirms the endpoint path, since a wrong path
  would 404, not 400), and once again through the actual `nodes.case_action
  .case_action` node end-to-end (`tests/fixtures/case_action_live_run_real
  .json`) using real `gather_evidence`+`rag_enrichment` output, a real
  `thehive_alert_id`, and `correlation_decision.action` forced to `"merge"`
  against the same test case — confirms the whole node's content-building,
  dispatch, and error-propagation path for real, even though the underlying
  TheHive call fails business-logic-wise (the expected, understood outcome).
- The `action == "new"` dispatch branch was also run live end-to-end (not
  captured to a fixture — a clean failure, nothing to regress-guard beyond
  what the mocked tests below already cover) against a syntactically valid
  but nonexistent alert id — real HTTP 404, `NotFoundError`, no crash.

Everything else here mocks `tools.thehive._write` or the four write
functions directly and checks orchestration logic only, per this repo's
standard split between real-backend verification and mocked regression
coverage.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest

from nodes import case_action as case_action_mod
from schemas import (
    ActionableObservable,
    AssetContext,
    CanonicalAlert,
    ContextualAssessment,
    CorrelationDecision,
    EnrichedEvidence,
    EvidenceSituation,
    ExtractedObservable,
    ExtractedObservables,
    Gap,
    Host,
    RawEvidence,
    Rule,
    RuleContext,
    ShallowCase,
    TriageVerdict,
)
from tools import thehive as th

CASE_ACTION_FIXTURE = Path(__file__).parent / "fixtures" / "case_action_live_run_real.json"


@pytest.fixture(scope="module")
def real() -> dict:
    return json.loads(CASE_ACTION_FIXTURE.read_text())


def run(coro):
    return asyncio.run(coro)


def fake_response(json_body: dict, status_code: int = 200) -> httpx.Response:
    request = httpx.Request("POST", "http://fake-thehive/api/v1/x")
    return httpx.Response(status_code, json=json_body, request=request)


def patch_write(monkeypatch, *, results=None, exc=None, capture=None):
    """Replace tools.thehive._write. `results` may be a list consumed in call
    order (for multi-call functions like create_case_from_alert), or a single
    httpx.Response reused for every call."""
    state = {"i": 0}

    async def fake_write(method, path, timeout, json_body=None):
        if capture is not None:
            capture.setdefault("calls", []).append((method, path, json_body))
        if exc is not None:
            raise exc
        if isinstance(results, list):
            out = results[min(state["i"], len(results) - 1)]
            state["i"] += 1
            return out
        return results

    monkeypatch.setattr(th, "_write", fake_write)


# ===========================================================================
# tools/thehive.py write functions
# ===========================================================================


class TestCreateCaseFromAlert:
    def test_happy_path_creates_then_patches(self, monkeypatch):
        capture: dict = {}
        create_resp = fake_response({"_id": "~123", "number": 7, "stage": "New", "status": "New"}, 201)
        patch_resp = fake_response({}, 204)
        patch_write(monkeypatch, results=[create_resp, patch_resp], capture=capture)

        shallow, gap = run(
            th.create_case_from_alert(
                "~alert1", title="My Title", description="desc", severity=3, tags=["t1"]
            )
        )

        assert gap is None
        assert shallow.case_id == "~123"
        assert shallow.case_number == 7
        assert shallow.title == "My Title"
        assert shallow.severity == 3
        assert capture["calls"][0][0] == "POST"
        assert capture["calls"][0][1] == "/api/v1/alert/~alert1/case"
        assert capture["calls"][1][0] == "PATCH"
        assert capture["calls"][1][1] == "/api/v1/case/~123"
        assert capture["calls"][1][2]["title"] == "My Title"
        assert capture["calls"][1][2]["severity"] == 3

    def test_no_alert_id_short_circuits(self, monkeypatch):
        called = {"n": 0}

        async def should_not_run(*a, **kw):
            called["n"] += 1

        monkeypatch.setattr(th, "_write", should_not_run)
        shallow, gap = run(
            th.create_case_from_alert("", title="x", description="x", severity=2)
        )
        assert shallow is None
        assert gap is not None
        assert called["n"] == 0

    def test_promote_failure_returns_gap(self, monkeypatch):
        patch_write(monkeypatch, exc=httpx.ConnectError("simulated"))
        shallow, gap = run(
            th.create_case_from_alert("~alert1", title="x", description="x", severity=2)
        )
        assert shallow is None
        assert gap is not None
        assert "Cannot connect" in gap.reason

    def test_content_patch_failure_still_returns_the_created_case(self, monkeypatch):
        """The case genuinely exists even if the content push failed — must
        not discard the case id, only report degraded content."""
        create_resp = fake_response({"_id": "~123", "number": 7}, 201)
        call_count = {"n": 0}

        async def fake_write(method, path, timeout, json_body=None):
            call_count["n"] += 1
            if method == "POST":
                return create_resp
            raise httpx.ConnectError("simulated PATCH failure")

        monkeypatch.setattr(th, "_write", fake_write)
        shallow, gap = run(
            th.create_case_from_alert("~alert1", title="x", description="x", severity=2)
        )
        assert shallow is not None
        assert shallow.case_id == "~123"
        assert gap is not None
        assert "~123" in gap.reason


class TestMergeAlertIntoCase:
    def test_happy_path(self, monkeypatch):
        capture: dict = {}
        patch_write(monkeypatch, results=fake_response({}, 200), capture=capture)
        ok, gap = run(th.merge_alert_into_case("~alert1", "~case1"))
        assert ok is True
        assert gap is None
        assert capture["calls"][0] == ("POST", "/api/v1/alert/~alert1/merge/~case1", {})

    def test_missing_ids_short_circuits(self, monkeypatch):
        called = {"n": 0}

        async def should_not_run(*a, **kw):
            called["n"] += 1

        monkeypatch.setattr(th, "_write", should_not_run)
        ok, gap = run(th.merge_alert_into_case("", "~case1"))
        assert ok is False
        assert called["n"] == 0

    def test_already_imported_failure_returns_gap(self, monkeypatch):
        """Reproduces the exact real failure this was live-verified against."""
        response = httpx.Response(
            400,
            json={"type": "BadRequest", "message": "Alert is already imported"},
            request=httpx.Request("POST", "http://fake/api/v1/alert/x/merge/y"),
        )
        patch_write(
            monkeypatch,
            exc=httpx.HTTPStatusError("400", request=response.request, response=response),
        )
        ok, gap = run(th.merge_alert_into_case("~alert1", "~case1"))
        assert ok is False
        assert "already imported" in gap.reason


class TestUpdateCase:
    def test_happy_path_severity_and_tags(self, monkeypatch):
        capture: dict = {}
        patch_write(monkeypatch, results=fake_response({}, 204), capture=capture)
        ok, gap = run(th.update_case("~case1", severity=4, add_tags=["x"]))
        assert ok is True
        assert capture["calls"][0][2] == {"severity": 4, "addTags": ["x"]}

    def test_no_fields_short_circuits(self, monkeypatch):
        called = {"n": 0}

        async def should_not_run(*a, **kw):
            called["n"] += 1

        monkeypatch.setattr(th, "_write", should_not_run)
        ok, gap = run(th.update_case("~case1"))
        assert ok is False
        assert called["n"] == 0

    def test_no_case_id_short_circuits(self, monkeypatch):
        ok, gap = run(th.update_case("", severity=2))
        assert ok is False
        assert "No case_id" in gap.reason


class TestAddCaseComment:
    def test_happy_path(self, monkeypatch):
        capture: dict = {}
        patch_write(
            monkeypatch, results=fake_response({"_id": "~c1"}, 201), capture=capture
        )
        ok, gap = run(th.add_case_comment("~case1", "hello"))
        assert ok is True
        assert capture["calls"][0] == ("POST", "/api/v1/case/~case1/comment", {"message": "hello"})

    def test_empty_comment_short_circuits(self, monkeypatch):
        ok, gap = run(th.add_case_comment("~case1", ""))
        assert ok is False


# ===========================================================================
# nodes/case_action.py — content builder
# ===========================================================================


def make_evidence(
    *, action_context: ContextualAssessment | None = None, thehive_alert_id: str = "~alert1"
) -> EnrichedEvidence:
    alert = CanonicalAlert(
        alert_id="~1",
        timestamp=datetime.now(timezone.utc),
        rule=Rule(name="Suspicious Invoke-WebRequest Execution", uuid="rule-uuid"),
        host=Host(hostname="win-test01"),
        thehive_alert_id=thehive_alert_id,
    )
    raw = RawEvidence(
        canonical_alert=alert,
        rule_context=RuleContext(found=True, level="high", mitre_attack=["T1105"]),
        asset_context=AssetContext(found=True, hostname="win-test01", criticality="high"),
        investigation_gaps=[Gap(source="opencti", reason="simulated gap", tool="opencti_observable_enrichment")],
    )
    return EnrichedEvidence(**raw.model_dump())


def make_evidence_situation(**overrides) -> EvidenceSituation:
    defaults = dict(sources=[], overall_evidence_reliability="high", analyst_must_verify=[])
    defaults.update(overrides)
    return EvidenceSituation(**defaults)


def make_context(
    *, action="new", merge_into_case_id=None, extracted_observables=None, evidence_situation=None
) -> ContextualAssessment:
    return ContextualAssessment(
        correlation_decision=CorrelationDecision(
            action=action, merge_into_case_id=merge_into_case_id, reasoning="test correlation"
        ),
        extracted_observables=extracted_observables or ExtractedObservables(),
        evidence_situation=evidence_situation or make_evidence_situation(),
    )


def make_extracted_observable(observable_type, value, *, rationale="test rationale"):
    return ExtractedObservable(
        observable_type=observable_type,
        value=value,
        rationale=rationale,
        confidence="high",
        source="behavioral_analysis",
    )


def make_actionable_observable(
    observable_type,
    value,
    *,
    disposition="block",
    confidence="high",
    reasoning="test reasoning",
) -> ActionableObservable:
    return ActionableObservable(
        observable_type=observable_type,
        value=value,
        recommended_disposition=disposition,
        confidence=confidence,
        reasoning=reasoning,
    )


def make_verdict(*, recommended_action="create_case", **overrides) -> TriageVerdict:
    """v5 (`newdesign.md` §6-§8): priority_band/priority_reasoning replace
    the deleted PriorityScore/make_priority() — case_action.py now reads
    priority straight off the verdict. Default P2 matches the old
    make_priority()'s default."""
    defaults = dict(
        likelihood="likely",
        impact_if_true="significant",
        verdict="true_positive",
        reasoning="test reasoning",
        summary="test summary",
        recommended_action=recommended_action,
        evidence_citations=["rule_context.severity=high"],
        priority_band="P2",
        priority_reasoning="test priority reasoning",
    )
    defaults.update(overrides)
    return TriageVerdict(**defaults)


class TestBuildCaseContent:
    def test_title_includes_priority_rule_and_host(self):
        """v5 (`newdesign.md` §8): title now leads with [priority_band]."""
        evidence = make_evidence()
        verdict = make_verdict(priority_band="P1")
        title = case_action_mod._build_case_title(verdict, evidence)
        assert "[P1]" in title
        assert "Suspicious Invoke-WebRequest Execution" in title
        assert "win-test01" in title

    def test_description_includes_verdict_and_reasoning(self):
        evidence = make_evidence()
        context = make_context()
        verdict = make_verdict()
        desc = case_action_mod._build_case_description(verdict, context, evidence)
        assert "true_positive" in desc
        assert "test reasoning" in desc
        assert "test summary" in desc
        assert "T1105" in desc

    def test_description_includes_evidence_situation_and_gaps(self):
        """v5 (`newdesign.md` §3-§4, §9) replaces the old contextual_modifiers
        assertion — the description now surfaces Stage 3's evidence_situation
        and Stage 4's own priority_reasoning/investigation_gaps instead."""
        evidence = make_evidence()
        context = make_context(
            evidence_situation=make_evidence_situation(
                sources=[
                    {
                        "source_name": "fp_signal",
                        "status": "missing",
                        "impact_on_triage": "fp_signal unavailable, cannot rule out known FP",
                    }
                ],
                overall_evidence_reliability="medium",
            )
        )
        verdict = make_verdict(
            priority_reasoning="P2 because confirmed malicious with no active spread",
            investigation_gaps=["Verify fp_signal manually — tool unavailable"],
        )
        desc = case_action_mod._build_case_description(verdict, context, evidence)
        assert "fp_signal unavailable, cannot rule out known FP" in desc
        assert "medium" in desc
        assert "P2 because confirmed malicious with no active spread" in desc
        assert "Verify fp_signal manually — tool unavailable" in desc
        assert "opencti_observable_enrichment" in desc

    def test_tags_include_priority_verdict_and_mitre(self):
        evidence = make_evidence()
        verdict = make_verdict(priority_band="P1")
        tags = case_action_mod._build_case_tags(verdict, evidence)
        assert "priority:P1" in tags
        assert "verdict:true_positive" in tags
        assert "T1105" in tags
        assert "soc3s-triage" in tags


# ===========================================================================
# nodes/case_action.py — dispatch logic
# ===========================================================================


class TestCaseActionDispatch:
    def test_new_action_calls_create(self, monkeypatch):
        captured = {}

        async def fake_create(alert_id, *, title, description, severity, tags=None, tlp=2, timeout=None):
            captured["called"] = "create"
            captured["severity"] = severity
            return ShallowCase(case_id="~new1", case_number=1, severity=severity), None

        async def should_not_run(*a, **kw):
            raise AssertionError("merge should not be called for action=='new'")

        monkeypatch.setattr(th, "create_case_from_alert", fake_create)
        monkeypatch.setattr(th, "merge_alert_into_case", should_not_run)

        evidence = make_evidence()
        context = make_context(action="new")
        verdict = make_verdict(priority_band="P1")

        result = run(case_action_mod.case_action(verdict, context, evidence))

        assert result.success is True
        assert result.is_new_case is True
        assert result.case_id == "~new1"
        assert captured["called"] == "create"
        assert captured["severity"] == 4  # P1 -> hive severity 4

    def test_merge_action_calls_merge_and_comment(self, monkeypatch):
        captured = {}

        async def fake_merge(alert_id, case_id, timeout=None):
            captured["merge_case_id"] = case_id
            return True, None

        async def fake_comment(case_id, comment, timeout=None):
            captured["comment_case_id"] = case_id
            captured["comment_text"] = comment
            return True, None

        async def should_not_update(*a, **kw):
            raise AssertionError("update_case should not be called for merge_quiet")

        monkeypatch.setattr(th, "merge_alert_into_case", fake_merge)
        monkeypatch.setattr(th, "add_case_comment", fake_comment)
        monkeypatch.setattr(th, "update_case", should_not_update)

        evidence = make_evidence()
        context = make_context(action="merge", merge_into_case_id="~existing1")
        verdict = make_verdict(recommended_action="merge_quiet")

        result = run(case_action_mod.case_action(verdict, context, evidence))

        assert result.success is True
        assert result.is_new_case is False
        assert result.case_id == "~existing1"
        assert result.comment_added is True
        assert captured["merge_case_id"] == "~existing1"
        assert captured["comment_case_id"] == "~existing1"

    def test_merge_and_retier_also_calls_update(self, monkeypatch):
        captured = {}

        async def fake_merge(alert_id, case_id, timeout=None):
            return True, None

        async def fake_update(case_id, *, severity=None, add_tags=None, timeout=None):
            captured["update_severity"] = severity
            return True, None

        async def fake_comment(case_id, comment, timeout=None):
            return True, None

        monkeypatch.setattr(th, "merge_alert_into_case", fake_merge)
        monkeypatch.setattr(th, "update_case", fake_update)
        monkeypatch.setattr(th, "add_case_comment", fake_comment)

        evidence = make_evidence()
        context = make_context(action="merge", merge_into_case_id="~existing1")
        verdict = make_verdict(recommended_action="merge_and_retier", priority_band="P1")

        result = run(case_action_mod.case_action(verdict, context, evidence))

        assert result.success is True
        assert captured["update_severity"] == 4  # P1 -> hive severity 4

    def test_null_merge_target_falls_back_to_create(self, monkeypatch):
        """Defensive path — action=='merge' but merge_into_case_id is None
        shouldn't happen (Stage 3's schema constraint + _validate_merge_target
        guarantee it), but must not crash if it somehow does."""
        captured = {}

        async def fake_create(alert_id, *, title, description, severity, tags=None, tlp=2, timeout=None):
            captured["called"] = True
            return ShallowCase(case_id="~fallback1"), None

        async def should_not_merge(*a, **kw):
            raise AssertionError("merge should not be attempted with no target case id")

        monkeypatch.setattr(th, "create_case_from_alert", fake_create)
        monkeypatch.setattr(th, "merge_alert_into_case", should_not_merge)

        evidence = make_evidence()
        context = make_context(action="merge", merge_into_case_id=None)
        verdict = make_verdict()

        result = run(case_action_mod.case_action(verdict, context, evidence))

        assert result.success is True
        assert result.case_id == "~fallback1"
        assert captured["called"] is True

    def test_create_failure_propagates_as_unsuccessful_result(self, monkeypatch):
        async def fake_create(*a, **kw):
            return None, Gap(source="thehive", reason="simulated failure", tool="create_case_from_alert")

        monkeypatch.setattr(th, "create_case_from_alert", fake_create)

        evidence = make_evidence()
        context = make_context(action="new")
        verdict = make_verdict()

        result = run(case_action_mod.case_action(verdict, context, evidence))

        assert result.success is False
        assert "simulated failure" in result.error

    def test_merge_failure_propagates_as_unsuccessful_result(self, monkeypatch):
        async def fake_merge(*a, **kw):
            return False, Gap(source="thehive", reason="simulated merge failure", tool="merge_alert_into_case")

        monkeypatch.setattr(th, "merge_alert_into_case", fake_merge)

        evidence = make_evidence()
        context = make_context(action="merge", merge_into_case_id="~existing1")
        verdict = make_verdict()

        result = run(case_action_mod.case_action(verdict, context, evidence))

        assert result.success is False
        assert "simulated merge failure" in result.error


# ===========================================================================
# nodes/case_action.py::_write_actionable_observables (2026-08-23)
#
# Replaces the old add_extracted_observables wiring — Stage 3's raw
# extraction is no longer written directly; Stage 4's per-item judgment
# (verdict.actionable_observables, each with a confidence) is, with a
# dedup lookup against what's already on the case. See case_action.py's
# module docstring for the full "why" of this change.
# ===========================================================================


class TestWriteActionableObservables:
    def test_no_observables_short_circuits(self, monkeypatch):
        async def should_not_run(*a, **kw):
            raise AssertionError("no HTTP calls should be made for an empty list")

        monkeypatch.setattr(th, "fetch_case_observables_with_type", should_not_run)
        monkeypatch.setattr(th, "create_case_observable", should_not_run)

        enriched, written, failed = run(
            case_action_mod._write_actionable_observables("~case1", [])
        )
        assert enriched == []
        assert written == 0
        assert failed == 0

    def test_new_observable_gets_created_and_id_captured(self, monkeypatch):
        async def fake_fetch(case_id, timeout=None):
            return [], None

        async def fake_create(case_id, *, data_type, data, tags=None, message="", ioc=True, timeout=None):
            return "~newid1", None

        monkeypatch.setattr(th, "fetch_case_observables_with_type", fake_fetch)
        monkeypatch.setattr(th, "create_case_observable", fake_create)

        item = make_actionable_observable("ip", "1.2.3.4")
        enriched, written, failed = run(
            case_action_mod._write_actionable_observables("~case1", [item])
        )

        assert written == 1
        assert failed == 0
        assert enriched[0].observable_id == "~newid1"

    def test_existing_observable_id_is_reused_not_duplicated(self, monkeypatch):
        async def fake_fetch(case_id, timeout=None):
            return [
                {"observable_id": "~existing1", "data_type": "ip", "value": "1.2.3.4", "tags": []}
            ], None

        async def should_not_create(*a, **kw):
            raise AssertionError("must not create a duplicate for an already-existing value")

        monkeypatch.setattr(th, "fetch_case_observables_with_type", fake_fetch)
        monkeypatch.setattr(th, "create_case_observable", should_not_create)

        item = make_actionable_observable("ip", "1.2.3.4")
        enriched, written, failed = run(
            case_action_mod._write_actionable_observables("~case1", [item])
        )

        assert written == 1
        assert failed == 0
        assert enriched[0].observable_id == "~existing1"

    def test_create_failure_still_returns_the_item_without_an_id(self, monkeypatch):
        """The LLM's judgment survives in the output even when the TheHive
        write itself failed — never silently dropped."""

        async def fake_fetch(case_id, timeout=None):
            return [], None

        async def fake_create(case_id, *, data_type, data, tags=None, message="", ioc=True, timeout=None):
            return None, Gap(source="thehive", tool="create_case_observable", reason="HTTP 400")

        monkeypatch.setattr(th, "fetch_case_observables_with_type", fake_fetch)
        monkeypatch.setattr(th, "create_case_observable", fake_create)

        item = make_actionable_observable("hash", "deadbeef")
        enriched, written, failed = run(
            case_action_mod._write_actionable_observables("~case1", [item])
        )

        assert written == 0
        assert failed == 1
        assert len(enriched) == 1
        assert enriched[0].observable_id is None

    def test_fetch_failure_does_not_block_creating_new_observables(self, monkeypatch):
        """A degraded existing-observables lookup shouldn't lose the write —
        worst case is a possible duplicate, not a dropped observable."""

        async def fake_fetch(case_id, timeout=None):
            return [], Gap(source="thehive", tool="fetch_case_observables_with_type", reason="down")

        async def fake_create(case_id, *, data_type, data, tags=None, message="", ioc=True, timeout=None):
            return "~newid1", None

        monkeypatch.setattr(th, "fetch_case_observables_with_type", fake_fetch)
        monkeypatch.setattr(th, "create_case_observable", fake_create)

        item = make_actionable_observable("ip", "1.2.3.4")
        enriched, written, failed = run(
            case_action_mod._write_actionable_observables("~case1", [item])
        )
        assert written == 1
        assert enriched[0].observable_id == "~newid1"

    def test_tags_reflect_disposition_and_confidence(self, monkeypatch):
        async def fake_fetch(case_id, timeout=None):
            return [], None

        captured = {}

        async def fake_create(case_id, *, data_type, data, tags=None, message="", ioc=True, timeout=None):
            captured.update(tags=tags, ioc=ioc, data_type=data_type)
            return "~newid1", None

        monkeypatch.setattr(th, "fetch_case_observables_with_type", fake_fetch)
        monkeypatch.setattr(th, "create_case_observable", fake_create)

        item = make_actionable_observable(
            "process-path", r"C:\evil.exe", disposition="block", confidence="high"
        )
        run(case_action_mod._write_actionable_observables("~case1", [item]))

        assert captured["tags"] == ["disposition:block", "confidence:high"]
        assert captured["ioc"] is True
        assert captured["data_type"] == "filename"

    def test_description_states_recommendation_and_reasoning(self, monkeypatch):
        """2026-08-23, user-directed: the TheHive observable's message
        (description) must state the recommended disposition up front,
        followed by the LLM's reasoning — not reasoning alone."""

        async def fake_fetch(case_id, timeout=None):
            return [], None

        captured = {}

        async def fake_create(case_id, *, data_type, data, tags=None, message="", ioc=True, timeout=None):
            captured["message"] = message
            return "~newid1", None

        monkeypatch.setattr(th, "fetch_case_observables_with_type", fake_fetch)
        monkeypatch.setattr(th, "create_case_observable", fake_create)

        item = make_actionable_observable(
            "hash",
            "deadbeef",
            disposition="block",
            confidence="high",
            reasoning="Matches a known-malicious hash per threat intel.",
        )
        run(case_action_mod._write_actionable_observables("~case1", [item]))

        assert captured["message"] == (
            "Recommendation: block. Matches a known-malicious hash per threat intel."
        )

    def test_already_exists_conflict_reuses_id_instead_of_failing(self, monkeypatch):
        """2026-08-23 live-caught race: TheHive's own alert-to-case import
        can land between the pre-check fetch and our create call. On that
        specific conflict, the item must be recovered via a re-fetch, not
        marked failed."""
        fetch_calls = []

        async def fake_fetch(case_id, timeout=None):
            fetch_calls.append(1)
            if len(fetch_calls) == 1:
                return [], None  # pre-check: value not visible yet
            return (
                [{"observable_id": "~racedid1", "data_type": "domain", "value": "github.com", "tags": []}],
                None,
            )

        async def fake_create(case_id, *, data_type, data, tags=None, message="", ioc=True, timeout=None):
            return None, Gap(
                source="thehive",
                tool="create_case_observable",
                reason="TheHive create-observable returned no object: "
                "{'success': [], 'failure': [{'type': 'CreateError', "
                "'message': 'Observable already exists', 'object': {'data': 'github.com'}}]}",
            )

        monkeypatch.setattr(th, "fetch_case_observables_with_type", fake_fetch)
        monkeypatch.setattr(th, "create_case_observable", fake_create)

        item = make_actionable_observable("domain", "github.com")
        enriched, written, failed = run(
            case_action_mod._write_actionable_observables("~case1", [item])
        )

        assert written == 1
        assert failed == 0
        assert enriched[0].observable_id == "~racedid1"
        assert len(fetch_calls) == 2  # pre-check + one conflict re-fetch

    def test_already_exists_conflict_without_a_match_still_counts_as_failed(self, monkeypatch):
        """If the re-fetch genuinely doesn't contain the value (a different,
        non-race conflict reason), the item must still be reported failed,
        not silently swallowed."""

        async def fake_fetch(case_id, timeout=None):
            return [], None

        async def fake_create(case_id, *, data_type, data, tags=None, message="", ioc=True, timeout=None):
            return None, Gap(
                source="thehive", tool="create_case_observable", reason="Observable already exists"
            )

        monkeypatch.setattr(th, "fetch_case_observables_with_type", fake_fetch)
        monkeypatch.setattr(th, "create_case_observable", fake_create)

        item = make_actionable_observable("domain", "github.com")
        enriched, written, failed = run(
            case_action_mod._write_actionable_observables("~case1", [item])
        )

        assert written == 0
        assert failed == 1
        assert enriched[0].observable_id is None

    def test_non_conflict_failure_does_not_trigger_a_refetch(self, monkeypatch):
        """A plain timeout/network failure must not pay the extra re-fetch
        cost — only the specific 'already exists' conflict does."""
        fetch_calls = []

        async def fake_fetch(case_id, timeout=None):
            fetch_calls.append(1)
            return [], None

        async def fake_create(case_id, *, data_type, data, tags=None, message="", ioc=True, timeout=None):
            return None, Gap(source="thehive", tool="create_case_observable", reason="Timeout after 5.0s")

        monkeypatch.setattr(th, "fetch_case_observables_with_type", fake_fetch)
        monkeypatch.setattr(th, "create_case_observable", fake_create)

        item = make_actionable_observable("domain", "github.com")
        enriched, written, failed = run(
            case_action_mod._write_actionable_observables("~case1", [item])
        )

        assert failed == 1
        assert len(fetch_calls) == 1  # only the initial pre-check, no conflict re-fetch

    def test_monitor_disposition_sets_ioc_false(self, monkeypatch):
        async def fake_fetch(case_id, timeout=None):
            return [], None

        captured = {}

        async def fake_create(case_id, *, data_type, data, tags=None, message="", ioc=True, timeout=None):
            captured["ioc"] = ioc
            return "~newid1", None

        monkeypatch.setattr(th, "fetch_case_observables_with_type", fake_fetch)
        monkeypatch.setattr(th, "create_case_observable", fake_create)

        item = make_actionable_observable(
            "domain", "maybe.example", disposition="monitor", confidence="low"
        )
        run(case_action_mod._write_actionable_observables("~case1", [item]))
        assert captured["ioc"] is False

    def test_process_path_and_file_share_datatype_but_get_independent_tags(self, monkeypatch):
        """Same trap tests/test_observable_writes.py's real fixture
        documented for the old bucket-write code (process/file both map to
        dataType 'filename', so dataType alone can't drive the tag decision)
        — now guarded against the new observable_type-keyed mapping."""

        async def fake_fetch(case_id, timeout=None):
            return [], None

        calls = []

        async def fake_create(case_id, *, data_type, data, tags=None, message="", ioc=True, timeout=None):
            calls.append({"data_type": data_type, "data": data, "tags": tags})
            return f"~id-{len(calls)}", None

        monkeypatch.setattr(th, "fetch_case_observables_with_type", fake_fetch)
        monkeypatch.setattr(th, "create_case_observable", fake_create)

        items = [
            make_actionable_observable("process-path", r"C:\evil.exe", disposition="block", confidence="high"),
            make_actionable_observable("file", "benign.dll", disposition="monitor", confidence="low"),
        ]
        run(case_action_mod._write_actionable_observables("~case1", items))

        by_data = {c["data"]: c for c in calls}
        assert by_data[r"C:\evil.exe"]["data_type"] == by_data["benign.dll"]["data_type"] == "filename"
        assert by_data[r"C:\evil.exe"]["tags"] != by_data["benign.dll"]["tags"]


# ===========================================================================
# nodes/case_action.py — observable-write wiring: dispatched at all, against
# the right case id, on both branches, gated behind a successful
# create/merge, and its failure never fails the node. The write mechanism
# itself is covered above in TestWriteActionableObservables.
# ===========================================================================


class TestCaseActionWritesObservables:
    def test_new_action_writes_to_the_created_case(self, monkeypatch):
        captured = {}

        async def fake_create(alert_id, *, title, description, severity, tags=None, tlp=2, timeout=None):
            return ShallowCase(case_id="~new1", case_number=1, severity=severity), None

        async def fake_write(case_id, actionable_observables):
            captured["case_id"] = case_id
            captured["items"] = actionable_observables
            return actionable_observables, len(actionable_observables), 0

        monkeypatch.setattr(th, "create_case_from_alert", fake_create)
        monkeypatch.setattr(case_action_mod, "_write_actionable_observables", fake_write)

        items = [make_actionable_observable("process-path", r"C:\Windows\Temp\xordump.exe")]
        result = run(
            case_action_mod.case_action(
                make_verdict(actionable_observables=items),
                make_context(action="new"),
                make_evidence(),
            )
        )

        # Written against the id the CREATE call returned, not the alert id.
        assert captured["case_id"] == "~new1"
        assert captured["items"] == items
        assert result.observables_written == 1
        assert result.observables_failed == 0
        assert result.actionable_observables_written == items

    def test_merge_action_writes_to_the_merge_target(self, monkeypatch):
        captured = {}

        async def fake_merge(alert_id, case_id, timeout=None):
            return True, None

        async def fake_comment(case_id, comment, timeout=None):
            return True, None

        async def fake_write(case_id, actionable_observables):
            captured["case_id"] = case_id
            return actionable_observables, len(actionable_observables), 0

        monkeypatch.setattr(th, "merge_alert_into_case", fake_merge)
        monkeypatch.setattr(th, "add_case_comment", fake_comment)
        monkeypatch.setattr(case_action_mod, "_write_actionable_observables", fake_write)

        items = [make_actionable_observable("process-path", r"C:\Windows\Temp\xordump.exe")]
        result = run(
            case_action_mod.case_action(
                make_verdict(recommended_action="merge_quiet", actionable_observables=items),
                make_context(action="merge", merge_into_case_id="~existing1"),
                make_evidence(),
            )
        )

        assert captured["case_id"] == "~existing1"
        assert result.observables_written == 1

    def test_failed_merge_does_not_write_observables(self, monkeypatch):
        """The write is gated behind a SUCCESSFUL merge — otherwise a wrong
        merge target would get observables written to it anyway."""

        async def fake_merge(*a, **kw):
            return False, Gap(source="thehive", reason="simulated", tool="merge_alert_into_case")

        async def should_not_run(*a, **kw):
            raise AssertionError("observables must not be written when the merge failed")

        monkeypatch.setattr(th, "merge_alert_into_case", fake_merge)
        monkeypatch.setattr(case_action_mod, "_write_actionable_observables", should_not_run)

        items = [make_actionable_observable("process-path", r"C:\evil.exe")]
        result = run(
            case_action_mod.case_action(
                make_verdict(actionable_observables=items),
                make_context(action="merge", merge_into_case_id="~existing1"),
                make_evidence(),
            )
        )
        assert result.success is False

    def test_failed_create_does_not_write_observables(self, monkeypatch):
        async def fake_create(*a, **kw):
            return None, Gap(source="thehive", reason="simulated", tool="create_case_from_alert")

        async def should_not_run(*a, **kw):
            raise AssertionError("observables must not be written when the case was never created")

        monkeypatch.setattr(th, "create_case_from_alert", fake_create)
        monkeypatch.setattr(case_action_mod, "_write_actionable_observables", should_not_run)

        items = [make_actionable_observable("process-path", r"C:\evil.exe")]
        result = run(
            case_action_mod.case_action(
                make_verdict(actionable_observables=items),
                make_context(action="new"),
                make_evidence(),
            )
        )
        assert result.success is False

    def test_observable_failure_never_fails_the_case_action(self, monkeypatch):
        """Observables are additive content on an already-successful case
        action — a failed write is recorded, never a gate."""

        async def fake_create(alert_id, *, title, description, severity, tags=None, tlp=2, timeout=None):
            return ShallowCase(case_id="~new1", case_number=1, severity=severity), None

        async def fake_write(case_id, actionable_observables):
            return actionable_observables, 0, 1

        monkeypatch.setattr(th, "create_case_from_alert", fake_create)
        monkeypatch.setattr(case_action_mod, "_write_actionable_observables", fake_write)

        items = [make_actionable_observable("process-path", r"C:\evil.exe")]
        result = run(
            case_action_mod.case_action(
                make_verdict(actionable_observables=items),
                make_context(action="new"),
                make_evidence(),
            )
        )

        assert result.success is True
        assert result.case_id == "~new1"
        assert result.observables_written == 0
        assert result.observables_failed == 1
        assert "observable" in result.error

    def test_empty_observables_make_no_write_call_at_all(self, monkeypatch):
        """The common benign-alert case: Stage 4 legitimately finds nothing
        actionable. Must not produce a Gap, an error, or an HTTP call."""

        async def fake_create(alert_id, *, title, description, severity, tags=None, tlp=2, timeout=None):
            return ShallowCase(case_id="~new1", case_number=1, severity=severity), None

        async def should_not_run(*a, **kw):
            raise AssertionError("no observable HTTP call should be made for an empty list")

        monkeypatch.setattr(th, "create_case_from_alert", fake_create)
        monkeypatch.setattr(th, "fetch_case_observables_with_type", should_not_run)
        monkeypatch.setattr(th, "create_case_observable", should_not_run)

        result = run(
            case_action_mod.case_action(
                make_verdict(), make_context(action="new"), make_evidence()
            )
        )

        assert result.success is True
        assert result.observables_written == 0
        assert result.observables_failed == 0
        assert result.error is None


# ===========================================================================
# Real fixture sanity
# ===========================================================================


class TestRealFixtureLooksReasonable:
    def test_validates_as_case_action_result(self, real):
        from schemas import CaseActionResult

        result = CaseActionResult.model_validate(real)
        assert result.case_id == "~8609848"

    def test_documents_the_expected_real_failure(self, real):
        """The real run intentionally targeted an already-imported alert —
        confirms the captured fixture is the understood failure, not a
        surprise."""
        assert real["success"] is False
        assert "already imported" in real["error"]
