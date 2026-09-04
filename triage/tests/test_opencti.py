"""`opencti_observable_enrichment` — a deployment-added Stage-1 tool, not in
architecture v4's original 7. See CLAUDE.md "Deployment-specific decisions:
OpenCTI" and `tools/opencti.py`'s module docstring.

PROVENANCE: `tests/fixtures/opencti_real.json` is REAL, captured live from
OpenCTI GraphQL 7.260318.0 at `172.20.24.222:8080` on 2026-08-13. A single
batched query for 4 values — two real threat-feed domains that resolve
(`w8p3k.com`, `yezi.haoyun.bar`) and two of this deployment's own alert
observables that do not (`github.com`, the alert's own sha256 hash) — proves
both the "found" and "not found" paths from ONE real call, and proves batched
exact-match filtering returns only genuine matches (4 values in, 2 edges out).
The tool itself was called live against the real backend before any of these
tests were written (implementation guide §2) — see the module docstring in
tools/opencti.py for the live smoke-test results.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from schemas import HashBundle, Observables
from tools import opencti as octi_mod
from tools.opencti import opencti_observable_enrichment

FIXTURE = Path(__file__).parent / "fixtures" / "opencti_real.json"


@pytest.fixture(scope="module")
def real() -> dict:
    """REAL — captured live from OpenCTI on 2026-08-13."""
    return json.loads(FIXTURE.read_text())


@pytest.fixture()
def real_edges(real) -> list:
    return real["batched_query_result"]["data"]["stixCyberObservables"]["edges"]


def patch_query(monkeypatch, edges=None, exc=None, capture=None):
    async def fake_query(filters, timeout):
        if capture is not None:
            capture["filters"] = filters
        if exc is not None:
            raise exc
        return edges or []

    monkeypatch.setattr(octi_mod, "_query", fake_query)


def run(coro):
    return asyncio.run(coro)


class TestRealBatchedLookup:
    def test_real_matches_are_found_true_with_data(self, monkeypatch, real_edges):
        obs = Observables(domains=["w8p3k.com", "yezi.haoyun.bar"])
        patch_query(monkeypatch, edges=real_edges)
        results, gap = run(opencti_observable_enrichment(obs))
        assert gap is None
        by_value = {r.observable: r for r in results}
        assert by_value["w8p3k.com"].found is True
        assert by_value["w8p3k.com"].opencti_score == 60
        assert "osint" in by_value["w8p3k.com"].labels
        assert "TLP:CLEAR" in by_value["w8p3k.com"].marking
        assert by_value["yezi.haoyun.bar"].found is True

    def test_real_non_matches_are_found_false_not_a_gap(self, monkeypatch, real_edges):
        """github.com and the alert's own sha256 hash genuinely aren't in this
        OpenCTI instance's data. That's a real, checked-and-empty answer, not
        a broken query — proven by the SAME call finding two real matches."""
        obs = Observables(
            domains=["github.com"],
            hashes=HashBundle(
                sha256=["1c84c8632c5269f24876ed9f49fa810b49f77e1e92e8918fc164c34b020f9a94"]
            ),
        )
        patch_query(monkeypatch, edges=real_edges)
        results, gap = run(opencti_observable_enrichment(obs))
        assert gap is None
        assert all(r.found is False for r in results)
        assert all(r.opencti_score is None for r in results)

    def test_indicator_names_survive_the_real_shape(self, monkeypatch, real_edges):
        obs = Observables(domains=["w8p3k.com"])
        patch_query(monkeypatch, edges=real_edges)
        results, _ = run(opencti_observable_enrichment(obs))
        assert results[0].indicator_names == ["w8p3k.com"]

    def test_relationship_with_no_attributable_entity_is_dropped_not_gapped(
        self, monkeypatch, real_edges
    ):
        """The real payload's `based-on` relationship resolves to an empty
        `to {}` (the target is another Indicator, not a Malware/IntrusionSet/
        ThreatActor/Campaign the inline fragments select on). That must be
        silently dropped from `relations`, not surfaced as noise or an error."""
        obs = Observables(domains=["w8p3k.com"])
        patch_query(monkeypatch, edges=real_edges)
        results, _ = run(opencti_observable_enrichment(obs))
        assert results[0].relations == []


class TestQueryConstruction:
    def test_batches_all_entity_kinds_into_one_filter(self, monkeypatch):
        capture: dict = {}
        patch_query(monkeypatch, edges=[], capture=capture)
        run(opencti_observable_enrichment(
            Observables(
                external_ips=["10.0.0.1"],
                domains=["evil.test"],
                urls=["https://e/x"],
                hashes=HashBundle(sha256=["a" * 64]),
            )
        ))
        values = capture["filters"]["filters"][0]["values"]
        for expected in ("10.0.0.1", "evil.test", "https://e/x", "a" * 64):
            assert expected in values

    def test_no_entities_gaps_rather_than_querying(self, monkeypatch):
        capture: dict = {}
        patch_query(monkeypatch, edges=[], capture=capture)
        results, gap = run(opencti_observable_enrichment(Observables()))
        assert results == []
        assert "no observables" in gap.reason.lower()
        assert capture == {}


class TestFailureModes:
    def test_timeout_is_a_gap(self, monkeypatch):
        async def slow_query(filters, timeout):
            await asyncio.sleep(10)

        monkeypatch.setattr(octi_mod, "_query", slow_query)
        results, gap = run(
            opencti_observable_enrichment(Observables(domains=["x.test"]), timeout=0.01)
        )
        assert results == []
        assert "timeout" in gap.reason.lower()

    def test_connection_error_is_a_gap(self, monkeypatch):
        patch_query(monkeypatch, exc=httpx.ConnectError("refused"))
        results, gap = run(opencti_observable_enrichment(Observables(domains=["x.test"])))
        assert results == []
        assert "Cannot connect to OpenCTI" in gap.reason

    def test_graphql_auth_error_is_a_gap_not_a_crash(self, monkeypatch):
        """The real shape a bad token returns (found live 2026-08-13 with the
        typo'd .mcp.json token): HTTP 200, `errors: [{code: AUTH_REQUIRED}]`."""
        request = httpx.Request("POST", "http://octi/graphql")
        response = httpx.Response(
            200,
            json={"errors": [{"message": "You must be logged in to do this."}], "data": None},
            request=request,
        )

        async def fake_query(filters, timeout):
            payload = response.json()
            messages = "; ".join(e.get("message", "") for e in payload["errors"])
            raise httpx.HTTPStatusError(f"GraphQL error: {messages}", request=request, response=response)

        monkeypatch.setattr(octi_mod, "_query", fake_query)
        results, gap = run(opencti_observable_enrichment(Observables(domains=["x.test"])))
        assert results == []
        assert "logged in" in gap.reason


class TestNodeMapping:
    def test_relations_map_malware_and_threat_actor(self):
        from tools.opencti import _node_to_enrichment

        node = {
            "observable_value": "evil.test",
            "entity_type": "Domain-Name",
            "x_opencti_score": 85,
            "objectLabel": [{"value": "apt"}],
            "objectMarking": [{"definition": "TLP:AMBER"}],
            "indicators": {"edges": [{"node": {"name": "evil.test"}}]},
            "stixCoreRelationships": {"edges": [
                {"node": {"relationship_type": "indicates", "to": {"name": "Emotet", "entity_type": "Malware"}}},
                {"node": {"relationship_type": "attributed-to", "to": {"name": "APT99", "entity_type": "ThreatActor"}}},
                {"node": {"relationship_type": "based-on", "to": {}}},
            ]},
        }
        enrichment = _node_to_enrichment(node)
        assert enrichment.found is True
        assert enrichment.opencti_score == 85
        assert len(enrichment.relations) == 2
        names = {r.related_entity_name for r in enrichment.relations}
        assert names == {"Emotet", "APT99"}

    def test_no_score_is_ever_computed_here(self):
        """A number DOES pass through (opencti_score), but it is OpenCTI's own
        foreign value, never derived from anything in this module — mirrors
        CortexResult.raw's treatment of foreign data. Confirmed by construction:
        no arithmetic on any field happens in _node_to_enrichment."""
        from tools.opencti import _node_to_enrichment

        node = {"observable_value": "x", "x_opencti_score": None}
        enrichment = _node_to_enrichment(node)
        assert enrichment.opencti_score is None
