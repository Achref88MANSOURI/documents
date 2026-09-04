"""`main.py` — the `/triage` HTTP entrypoint (architecture §3, file-tree spec).
No node/tool internals are re-tested here (each already has its own test
file) — this file only exercises `main.py`'s own orchestration logic: the
Stage 1->6 call sequence, `TriageResult` assembly, and the "HTTP 200 always,
success=False + failed_stage on any unexpected failure" posture (CLAUDE.md,
2026-08-23 build writeup). Every node function is monkeypatched at its
`main.py` import site (`main.gather_mod`, `main.rag_mod`, etc. — `main.py`
does `from nodes import gather as gather_mod` etc., the same
patch-at-the-module-object convention `tests/test_gather.py` already uses),
never the real backends.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

import main
from schemas import (
    CanonicalAlert,
    CaseActionResult,
    ContextualAssessment,
    CorrelationDecision,
    EnrichedEvidence,
    EvidenceSituation,
    Gap,
    Host,
    RawEvidence,
    Rule,
    TriageVerdict,
    User,
)

client = TestClient(main.app)

PAYLOAD = {
    "thehive_alert_id": "~1",
    "raw_alert": {"event": {"dataset": "sigma.alert"}},
    "asset_context": {},
}


def make_alert() -> CanonicalAlert:
    return CanonicalAlert(
        alert_id="~1",
        timestamp=datetime.now(timezone.utc),
        rule=Rule(name="test rule", uuid="x"),
        host=Host(hostname="win-test"),
        user=User(name="tester"),
    )


def make_evidence() -> EnrichedEvidence:
    raw = RawEvidence(canonical_alert=make_alert())
    return EnrichedEvidence(**raw.model_dump())


def make_context() -> ContextualAssessment:
    return ContextualAssessment(
        correlation_decision=CorrelationDecision(action="new", reasoning="x"),
        evidence_situation=EvidenceSituation(
            sources=[], overall_evidence_reliability="high", analyst_must_verify=[]
        ),
    )


def make_verdict() -> TriageVerdict:
    return TriageVerdict(
        likelihood="likely",
        impact_if_true="significant",
        verdict="true_positive",
        reasoning="x",
        summary="x",
        recommended_action="create_case",
        priority_band="P2",
        priority_reasoning="test priority reasoning",
    )


@pytest.fixture(autouse=True)
def patch_ingestion(monkeypatch):
    """Every test needs the alert-detail fetch + canonical alert build to
    succeed with something plausible — patched once here, individual tests
    override further downstream stages as needed."""

    async def fake_get_full_alert(thehive_alert_id, timeout=None):
        return {"title": "t"}, None

    monkeypatch.setattr(main.thehive, "get_full_alert_with_analysis", fake_get_full_alert)
    monkeypatch.setattr(main.alert_builder, "build_canonical_alert", lambda *a, **kw: make_alert())


class TestHappyPath:
    def test_full_pipeline_success(self, monkeypatch):
        async def fake_gather(alert):
            return RawEvidence(canonical_alert=alert)

        async def fake_rag(raw_evidence):
            return EnrichedEvidence(**raw_evidence.model_dump())

        async def fake_context(evidence):
            return make_context()

        async def fake_analyze(context, evidence):
            return make_verdict()

        async def fake_case_action(verdict, context, evidence):
            return CaseActionResult(success=True, case_id="~999", is_new_case=True)

        monkeypatch.setattr(main.gather_mod, "gather_evidence", fake_gather)
        monkeypatch.setattr(main.rag_mod, "rag_enrichment", fake_rag)
        monkeypatch.setattr(main.context_mod, "context_analysis", fake_context)
        monkeypatch.setattr(main.analyze_mod, "analyst_verdict", fake_analyze)
        # v5 (newdesign.md §5) — no more score_mod: _build_triage_result is a
        # pure, math-free function in main.py itself, run for real here (no
        # I/O, deterministic from the already-mocked verdict/context).
        monkeypatch.setattr(main.case_action_mod, "case_action", fake_case_action)

        resp = client.post("/triage", json=PAYLOAD)

        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is True
        assert body["error"] is None
        assert body["failed_stage"] is None
        assert body["result"]["alert_id"] == "~1"
        assert body["result"]["case_action"]["case_id"] == "~999"

    def test_degraded_hive_alert_fetch_does_not_block_success(self, monkeypatch):
        """A Gap from get_full_alert_with_analysis is logged, not fatal —
        matches that function's own NEVER RAISES contract."""

        async def fake_get_full_alert(thehive_alert_id, timeout=None):
            return None, Gap(source="thehive", tool="get_full_alert_with_analysis", reason="down")

        monkeypatch.setattr(main.thehive, "get_full_alert_with_analysis", fake_get_full_alert)

        async def fake_gather(alert):
            return RawEvidence(canonical_alert=alert)

        async def fake_rag(raw_evidence):
            return EnrichedEvidence(**raw_evidence.model_dump())

        monkeypatch.setattr(main.gather_mod, "gather_evidence", fake_gather)
        monkeypatch.setattr(main.rag_mod, "rag_enrichment", fake_rag)
        monkeypatch.setattr(main.context_mod, "context_analysis", lambda e: _async(make_context()))
        monkeypatch.setattr(main.analyze_mod, "analyst_verdict", lambda c, e: _async(make_verdict()))
        monkeypatch.setattr(
            main.case_action_mod,
            "case_action",
            lambda v, c, e: _async(CaseActionResult(success=True, case_id="~1")),
        )

        resp = client.post("/triage", json=PAYLOAD)
        assert resp.status_code == 200
        assert resp.json()["success"] is True


async def _async(value):
    return value


class TestFailurePosture:
    """HTTP 200 always, success=False + failed_stage on an unexpected
    failure — the user-directed posture this repo now follows."""

    def test_stage_failure_returns_200_with_error_and_failed_stage(self, monkeypatch):
        async def fake_gather(alert):
            return RawEvidence(canonical_alert=alert)

        async def raises(*args, **kwargs):
            raise RuntimeError("rag backend exploded")

        monkeypatch.setattr(main.gather_mod, "gather_evidence", fake_gather)
        monkeypatch.setattr(main.rag_mod, "rag_enrichment", raises)

        resp = client.post("/triage", json=PAYLOAD)

        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is False
        assert body["failed_stage"] == "rag"
        assert "rag backend exploded" in body["error"]
        assert body["result"] is None

    def test_failure_after_score_preserves_partial_result(self, monkeypatch):
        """A failure in case_action (Stage 6) must not discard the Stage 5
        TriageResult already built — n8n still gets the score/verdict."""

        async def fake_gather(alert):
            return RawEvidence(canonical_alert=alert)

        async def fake_rag(raw_evidence):
            return EnrichedEvidence(**raw_evidence.model_dump())

        async def raises(*args, **kwargs):
            raise RuntimeError("thehive down")

        monkeypatch.setattr(main.gather_mod, "gather_evidence", fake_gather)
        monkeypatch.setattr(main.rag_mod, "rag_enrichment", fake_rag)
        monkeypatch.setattr(main.context_mod, "context_analysis", lambda e: _async(make_context()))
        monkeypatch.setattr(main.analyze_mod, "analyst_verdict", lambda c, e: _async(make_verdict()))
        monkeypatch.setattr(main.case_action_mod, "case_action", raises)

        resp = client.post("/triage", json=PAYLOAD)

        assert resp.status_code == 200
        body = resp.json()
        assert body["success"] is False
        assert body["failed_stage"] == "case_action"
        assert body["result"] is not None
        assert body["result"]["alert_id"] == "~1"
        assert body["result"]["case_action"] is None


class TestHealth:
    def test_health_ok(self, monkeypatch):
        class FakeResponse:
            def raise_for_status(self):
                pass

        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def get(self, *a, **kw):
                return FakeResponse()

        monkeypatch.setattr(main.httpx, "AsyncClient", lambda: FakeClient())

        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_health_degraded_on_unreachable_backend(self, monkeypatch):
        class FakeClient:
            async def __aenter__(self):
                return self

            async def __aexit__(self, *a):
                return False

            async def get(self, *a, **kw):
                raise ConnectionError("refused")

        monkeypatch.setattr(main.httpx, "AsyncClient", lambda: FakeClient())

        resp = client.get("/health")
        assert resp.status_code == 503
        assert resp.json()["status"] == "degraded"
