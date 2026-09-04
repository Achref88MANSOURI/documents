"""`elasticsearch_related_alerts` and `elasticsearch_process_history` —
architecture §6 tools 6 and 7.

PROVENANCE: `tests/fixtures/es_related_alerts_real.json` and
`tests/fixtures/es_process_history_real.json` are ACTUAL captured responses
from the live cluster on 2026-08-13, queried for host `win-kvkmd51ggkq` /
user `Administrator` over a 60-day window (`.ds-logs-detections.alerts-so-*`
and `.ds-logs-endpoint.events.process-*` respectively). Each live query
returned 50 hits; both fixtures keep the first 5, verbatim and unedited, per
fixture-discipline size limits — the shape is unchanged, only the hit count is
truncated. Both tools were called against the real backend before any of
these tests were written (implementation guide §2).

`tests/fixtures/es_related_alerts_suricata_real.json` (added 2026-08-21, gap
#17) is likewise an ACTUAL captured response, from `logs-suricata.alerts-so*`,
queried by the real, currently-firing `network.community_id` of the "ET
CURRENT_EVENTS [Fireeye] Backdoor.HTTP.GORAT" rule (SID 2031297). The live
query returned 50 hits (capped); this fixture keeps the first 3. Two fields
are additionally stripped from each kept hit, NOT for fixture-discipline size
reasons alone but because they are pure duplicates of already-present
structured fields and neither is read by any code: `message` (the raw EVE
JSON string — every value in it also appears structured elsewhere in the same
document) and `network.data` (the decoded packet payload). `dns.query_name`
is deliberately KEPT despite being just as large a class of noise, because
it is a real trap documented in `tools/elasticsearch.py`'s module
docstring — all 5 originally-captured hits had the IDENTICAL
`dns.query_name` value, confirming it is the rule's static `content:` match
bytes, not per-alert DNS data. A test below asserts on its presence to keep
that finding regression-guarded, the same rationale CLAUDE.md's fixture
discipline uses for keeping `ioc.*` in the Sigma fixture.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from schemas import Host, Network, Observables, User
from tools import elasticsearch as es_tool
from tools.elasticsearch import elasticsearch_process_history, elasticsearch_related_alerts

RELATED_FIXTURE = Path(__file__).parent / "fixtures" / "es_related_alerts_real.json"
PROCESS_FIXTURE = Path(__file__).parent / "fixtures" / "es_process_history_real.json"
RELATED_SURICATA_FIXTURE = (
    Path(__file__).parent / "fixtures" / "es_related_alerts_suricata_real.json"
)

REAL_HOST = Host(hostname="win-kvkmd51ggkq")
REAL_USER = User(name="Administrator")
REAL_SURICATA_NETWORK = Network(
    community_id="1:nnE9J7ZfZe4S6M2FBlhXah2bp0w=",
    src_ip="172.20.24.101",
    dst_ip="172.20.24.102",
)


@pytest.fixture
def real_related_response() -> dict:
    """REAL — captured live from `.ds-logs-detections.alerts-so-*` on
    2026-08-13, first 5 of 50 hits kept verbatim."""
    return json.loads(RELATED_FIXTURE.read_text())


@pytest.fixture
def real_process_response() -> dict:
    """REAL — captured live from `.ds-logs-endpoint.events.process-*` on
    2026-08-13, first 5 of 50 hits kept verbatim."""
    return json.loads(PROCESS_FIXTURE.read_text())


@pytest.fixture
def real_related_suricata_response() -> dict:
    """REAL — captured live from `logs-suricata.alerts-so*` on 2026-08-21,
    first 3 of 50 hits kept, `message`/`network.data` stripped (see module
    docstring)."""
    return json.loads(RELATED_SURICATA_FIXTURE.read_text())


def patch_es(monkeypatch, result=None, exc=None, capture=None):
    """Replace the ES transport. The tool's own logic is what's under test."""

    async def fake_es_search(index, body, timeout):
        if capture is not None:
            capture.update({"index": index, "body": body, "timeout": timeout})
        if exc is not None:
            raise exc
        return result

    monkeypatch.setattr(es_tool, "es_search", fake_es_search)


def run(coro):
    return asyncio.run(coro)


# ===========================================================================
# elasticsearch_related_alerts — REAL captured response
# ===========================================================================
class TestRelatedAlertsAgainstRealCapturedResponse:
    def test_no_gap_and_populated(self, monkeypatch, real_related_response):
        patch_es(monkeypatch, result=real_related_response)
        summaries, gap = run(
            elasticsearch_related_alerts(
                REAL_HOST, REAL_USER, None, investigation_profile="endpoint_behavior", hours=24
            )
        )
        assert gap is None
        assert len(summaries) == 5

    def test_field_mapping_from_real_hit(self, monkeypatch, real_related_response):
        patch_es(monkeypatch, result=real_related_response)
        summaries, _ = run(
            elasticsearch_related_alerts(
                REAL_HOST, REAL_USER, None, investigation_profile="endpoint_behavior", hours=24
            )
        )
        first = summaries[0]
        raw = real_related_response["hits"]["hits"][0]["_source"]
        assert first.rule_name == raw["rule"]["name"]
        assert first.rule_uuid == raw["rule"]["uuid"]
        assert first.severity == raw["event"]["severity"]
        assert first.host == raw["event_data"]["host"]["name"]
        assert first.user == raw["event_data"]["user"]["name"]
        assert first.alert_id == real_related_response["hits"]["hits"][0]["_id"]

    def test_rule_uuid_read_from_top_level_not_ioc(self, monkeypatch, real_related_response):
        """The real document also carries `ioc.rule.uuid`. CLAUDE.md is
        explicit: `ioc.*` must never be read. On this fixture the two values
        happen to be equal, so this only proves the mapping targets the right
        key structurally; the synthetic test below proves it picks the right
        one when they diverge."""
        raw = real_related_response["hits"]["hits"][0]["_source"]
        assert "ioc" in raw  # sanity: the temptation is really there
        patch_es(monkeypatch, result=real_related_response)
        summaries, _ = run(
            elasticsearch_related_alerts(
                REAL_HOST, REAL_USER, None, investigation_profile="endpoint_behavior", hours=24
            )
        )
        assert summaries[0].rule_uuid == raw["rule"]["uuid"]

    def test_zero_hits_is_a_valid_empty_result(self, monkeypatch):
        patch_es(monkeypatch, result={"hits": {"hits": []}})
        summaries, gap = run(
            elasticsearch_related_alerts(
                REAL_HOST, REAL_USER, None, investigation_profile="endpoint_behavior", hours=24
            )
        )
        assert gap is None
        assert summaries == []


# ===========================================================================
# elasticsearch_related_alerts — the query itself
# ===========================================================================
class TestRelatedAlertsQueryConstruction:
    def test_index_and_size_and_sort(self, monkeypatch, real_related_response):
        capture: dict = {}
        patch_es(monkeypatch, result=real_related_response, capture=capture)
        run(elasticsearch_related_alerts(
                REAL_HOST, REAL_USER, None, investigation_profile="endpoint_behavior", hours=24
            ))
        assert capture["index"] == "logs-detections.alerts-so*"
        assert capture["body"]["size"] == 50
        assert capture["body"]["sort"] == [
            {"@timestamp": {"order": "desc", "unmapped_type": "date"}}
        ]

    def test_hours_reflected_in_range_filter(self, monkeypatch, real_related_response):
        capture: dict = {}
        patch_es(monkeypatch, result=real_related_response, capture=capture)
        run(elasticsearch_related_alerts(
                REAL_HOST, REAL_USER, None, investigation_profile="endpoint_behavior", hours=48
            ))
        filters = capture["body"]["query"]["bool"]["filter"]
        assert {"range": {"@timestamp": {"gte": "now-48h"}}} in filters

    def test_host_and_user_become_should_clauses(self, monkeypatch, real_related_response):
        capture: dict = {}
        patch_es(monkeypatch, result=real_related_response, capture=capture)
        run(elasticsearch_related_alerts(
                REAL_HOST, REAL_USER, None, investigation_profile="endpoint_behavior", hours=24
            ))
        should = capture["body"]["query"]["bool"]["should"]
        assert {"term": {"event_data.host.name": "win-kvkmd51ggkq"}} in should
        assert {"term": {"event_data.user.name": "Administrator"}} in should
        assert capture["body"]["query"]["bool"]["minimum_should_match"] == 1

    def test_hash_observables_become_should_clause_against_related_hash(
        self, monkeypatch, real_related_response
    ):
        """`event_data.related.hash` — live-confirmed populated on 332 real
        alert docs (module docstring probe, 2026-08-13); `event_data.process
        .hash.*` is not used for correlation, `related.hash` already covers it
        as one flat multi-algorithm list."""
        capture: dict = {}
        patch_es(monkeypatch, result=real_related_response, capture=capture)
        observables = Observables(hashes={"sha256": ["deadbeef"]})
        run(elasticsearch_related_alerts(
                None, None, observables, investigation_profile="endpoint_behavior", hours=24
            ))
        should = capture["body"]["query"]["bool"]["should"]
        assert {"terms": {"event_data.related.hash": ["deadbeef"]}} in should

    def test_hash_observables_combine_all_algorithms_into_one_clause(
        self, monkeypatch, real_related_response
    ):
        """`related.hash` mixes algorithms on the same document (a real sample
        holds a sha256 and two md5-length values together) — so all typed
        `HashBundle` values are flattened into a single `terms` list rather
        than one clause per algorithm."""
        capture: dict = {}
        patch_es(monkeypatch, result=real_related_response, capture=capture)
        observables = Observables(hashes={"md5": ["aaa"], "sha256": ["bbb"]})
        run(elasticsearch_related_alerts(
                None, None, observables, investigation_profile="endpoint_behavior", hours=24
            ))
        should = capture["body"]["query"]["bool"]["should"]
        hash_clauses = [c for c in should if "event_data.related.hash" in c.get("terms", {})]
        assert len(hash_clauses) == 1
        assert set(hash_clauses[0]["terms"]["event_data.related.hash"]) == {"aaa", "bbb"}

    def test_external_ips_become_should_clause_against_related_ip(
        self, monkeypatch, real_related_response
    ):
        """`event_data.related.ip` — live-confirmed populated on 4708 real
        alert docs (module docstring probe, 2026-08-13). `event_data
        .destination.ip` was probed at the same time and found on 0 docs, so
        it is deliberately not used."""
        capture: dict = {}
        patch_es(monkeypatch, result=real_related_response, capture=capture)
        observables = Observables(external_ips=["192.168.1.73"])
        run(elasticsearch_related_alerts(
                None, None, observables, investigation_profile="endpoint_behavior", hours=24
            ))
        should = capture["body"]["query"]["bool"]["should"]
        assert {"terms": {"event_data.related.ip": ["192.168.1.73"]}} in should

    def test_domains_and_urls_produce_no_should_clause(self, monkeypatch, real_related_response):
        """No live-verified field carries these yet (module docstring probe:
        `event_data.url.*` and `event_data.dns.question.name` are 0-populated
        across the whole index). Only `external_ips` should influence the
        query when domains/urls are also set."""
        capture: dict = {}
        patch_es(monkeypatch, result=real_related_response, capture=capture)
        observables = Observables(
            external_ips=["192.168.1.73"],
            domains=["evil.example"],
            urls=["https://evil.example/payload"],
        )
        run(elasticsearch_related_alerts(
                None, None, observables, investigation_profile="endpoint_behavior", hours=24
            ))
        should = capture["body"]["query"]["bool"]["should"]
        assert should == [{"terms": {"event_data.related.ip": ["192.168.1.73"]}}]

    def test_timeout_is_passed_through(self, monkeypatch, real_related_response):
        capture: dict = {}
        patch_es(monkeypatch, result=real_related_response, capture=capture)
        run(elasticsearch_related_alerts(
                REAL_HOST, REAL_USER, None, investigation_profile="endpoint_behavior", timeout=1.5
            ))
        assert capture["timeout"] == 1.5

    def test_no_correlation_input_short_circuits_without_calling_es(self, monkeypatch):
        called = {"n": 0}

        async def should_not_run(index, body, timeout):
            called["n"] += 1
            return {}

        monkeypatch.setattr(es_tool, "es_search", should_not_run)
        summaries, gap = run(
            elasticsearch_related_alerts(
                None, None, None, investigation_profile="endpoint_behavior"
            )
        )
        assert summaries == []
        assert gap is not None
        assert "nothing to correlate" in gap.reason
        assert called["n"] == 0

    def test_unsupported_profile_short_circuits_without_calling_es(self, monkeypatch):
        """`malicious_file` (YARA/Strelka) and the `generic` fallback have no
        verified correlation query — gap #17's dispatcher must return an
        explicit Gap for them rather than silently running the Sigma-shaped
        query (the original bug: it ran regardless of engine and returned an
        empty list with no Gap for anything non-Sigma)."""
        called = {"n": 0}

        async def should_not_run(index, body, timeout):
            called["n"] += 1
            return {}

        monkeypatch.setattr(es_tool, "es_search", should_not_run)
        summaries, gap = run(
            elasticsearch_related_alerts(
                REAL_HOST, REAL_USER, None, investigation_profile="malicious_file"
            )
        )
        assert summaries == []
        assert gap is not None
        assert "malicious_file" in gap.reason
        assert called["n"] == 0

        summaries, gap = run(elasticsearch_related_alerts(REAL_HOST, REAL_USER, None))
        assert summaries == []
        assert gap is not None
        assert "'generic'" in gap.reason
        assert called["n"] == 0


# ===========================================================================
# elasticsearch_related_alerts — failure paths
# ===========================================================================
class TestRelatedAlertsFailuresProduceGapsNotExceptions:
    def test_connection_error(self, monkeypatch):
        patch_es(monkeypatch, exc=httpx.ConnectError("connection refused"))
        summaries, gap = run(
            elasticsearch_related_alerts(
                REAL_HOST, REAL_USER, None, investigation_profile="endpoint_behavior"
            )
        )
        assert summaries == []
        assert gap is not None
        assert gap.tool == "elasticsearch_related_alerts"
        assert "Cannot connect to Elasticsearch" in gap.reason

    def test_http_error_includes_status_and_body(self, monkeypatch):
        response = httpx.Response(
            403, text="access denied", request=httpx.Request("POST", "https://es/_search")
        )
        patch_es(
            monkeypatch,
            exc=httpx.HTTPStatusError("boom", request=response.request, response=response),
        )
        _, gap = run(
            elasticsearch_related_alerts(
                REAL_HOST, REAL_USER, None, investigation_profile="endpoint_behavior"
            )
        )
        assert "HTTP 403" in gap.reason
        assert "access denied" in gap.reason

    def test_timeout_produces_gap(self, monkeypatch):
        async def slow(index, body, timeout):
            await asyncio.sleep(5)

        monkeypatch.setattr(es_tool, "es_search", slow)
        summaries, gap = run(
            elasticsearch_related_alerts(
                REAL_HOST,
                REAL_USER,
                None,
                investigation_profile="endpoint_behavior",
                timeout=0.05,
            )
        )
        assert summaries == []
        assert "Timeout after 0.05s" in gap.reason
        assert gap.duration_ms is not None


# ===========================================================================
# elasticsearch_related_alerts — Suricata path (gap #17), REAL captured response
# ===========================================================================
class TestRelatedAlertsSuricataAgainstRealCapturedResponse:
    def test_no_gap_and_populated(self, monkeypatch, real_related_suricata_response):
        patch_es(monkeypatch, result=real_related_suricata_response)
        summaries, gap = run(
            elasticsearch_related_alerts(
                None,
                None,
                None,
                network=REAL_SURICATA_NETWORK,
                investigation_profile="network_threat",
                hours=24,
            )
        )
        assert gap is None
        assert len(summaries) == 3

    def test_field_mapping_from_real_hit(self, monkeypatch, real_related_suricata_response):
        patch_es(monkeypatch, result=real_related_suricata_response)
        summaries, _ = run(
            elasticsearch_related_alerts(
                None,
                None,
                None,
                network=REAL_SURICATA_NETWORK,
                investigation_profile="network_threat",
                hours=24,
            )
        )
        first = summaries[0]
        raw = real_related_suricata_response["hits"]["hits"][0]["_source"]
        assert first.rule_name == raw["rule"]["name"]
        assert first.rule_uuid == raw["rule"]["uuid"]  # Suricata SID, e.g. "2031297"
        assert first.severity == raw["event"]["severity"]
        assert first.alert_id == real_related_suricata_response["hits"]["hits"][0]["_id"]

    def test_host_and_user_always_none(self, monkeypatch, real_related_suricata_response):
        """Suricata alert documents have no host/user concept at all — unlike
        the Sigma path, this isn't a missing-field default, it's the correct
        mapping for a document shape that structurally cannot carry it."""
        patch_es(monkeypatch, result=real_related_suricata_response)
        summaries, _ = run(
            elasticsearch_related_alerts(
                None,
                None,
                None,
                network=REAL_SURICATA_NETWORK,
                investigation_profile="network_threat",
                hours=24,
            )
        )
        assert all(s.host is None and s.user is None for s in summaries)

    def test_dns_query_name_trap_is_present_but_never_read(
        self, monkeypatch, real_related_suricata_response
    ):
        """Regression guard for the trap documented in this module's docstring
        and in `tools/elasticsearch.py`: `dns.query_name` looks like real DNS
        evidence and is populated on every real hit, but it's the firing
        rule's own static `content:` match bytes, not per-alert data — proven
        here by it being IDENTICAL across every kept hit despite each hit
        being a distinct alert instance. No field of `AlertSummary` may ever
        be sourced from it."""
        hits = real_related_suricata_response["hits"]["hits"]
        query_names = {h["_source"]["dns"]["query_name"] for h in hits}
        assert len(query_names) == 1  # identical across distinct alerts -> not real DNS data
        patch_es(monkeypatch, result=real_related_suricata_response)
        summaries, _ = run(
            elasticsearch_related_alerts(
                None,
                None,
                None,
                network=REAL_SURICATA_NETWORK,
                investigation_profile="network_threat",
                hours=24,
            )
        )
        for s in summaries:
            assert list(query_names)[0] not in (s.rule_name or "")

    def test_zero_hits_is_a_valid_empty_result(self, monkeypatch):
        patch_es(monkeypatch, result={"hits": {"hits": []}})
        summaries, gap = run(
            elasticsearch_related_alerts(
                None,
                None,
                None,
                network=REAL_SURICATA_NETWORK,
                investigation_profile="network_threat",
                hours=24,
            )
        )
        assert gap is None
        assert summaries == []


# ===========================================================================
# elasticsearch_related_alerts — Suricata path, the query itself
# ===========================================================================
class TestRelatedAlertsSuricataQueryConstruction:
    def test_index_and_size_and_sort(self, monkeypatch, real_related_suricata_response):
        capture: dict = {}
        patch_es(monkeypatch, result=real_related_suricata_response, capture=capture)
        run(
            elasticsearch_related_alerts(
                None,
                None,
                None,
                network=REAL_SURICATA_NETWORK,
                investigation_profile="network_threat",
                hours=24,
            )
        )
        assert capture["index"] == "logs-suricata.alerts-so*"
        assert capture["body"]["size"] == 50
        assert capture["body"]["sort"] == [
            {"@timestamp": {"order": "desc", "unmapped_type": "date"}}
        ]

    def test_community_id_and_ips_become_should_clauses(
        self, monkeypatch, real_related_suricata_response
    ):
        capture: dict = {}
        patch_es(monkeypatch, result=real_related_suricata_response, capture=capture)
        run(
            elasticsearch_related_alerts(
                None,
                None,
                None,
                network=REAL_SURICATA_NETWORK,
                investigation_profile="network_threat",
                hours=24,
            )
        )
        should = capture["body"]["query"]["bool"]["should"]
        assert {"term": {"network.community_id": "1:nnE9J7ZfZe4S6M2FBlhXah2bp0w="}} in should
        assert {"term": {"source.ip": "172.20.24.101"}} in should
        assert {"term": {"destination.ip": "172.20.24.102"}} in should
        assert capture["body"]["query"]["bool"]["minimum_should_match"] == 1

    def test_ioc_ips_become_should_clauses_against_source_and_destination(
        self, monkeypatch, real_related_suricata_response
    ):
        """IOC IPs correlate against both `source.ip` and `destination.ip` —
        an IP could be either side of a different flow, unlike the alert's
        own network object where src/dst are already fixed roles."""
        capture: dict = {}
        patch_es(monkeypatch, result=real_related_suricata_response, capture=capture)
        observables = Observables(external_ips=["203.0.113.9"])
        run(
            elasticsearch_related_alerts(
                None,
                None,
                observables,
                investigation_profile="network_threat",
                hours=24,
            )
        )
        should = capture["body"]["query"]["bool"]["should"]
        assert {"terms": {"source.ip": ["203.0.113.9"]}} in should
        assert {"terms": {"destination.ip": ["203.0.113.9"]}} in should

    def test_no_correlation_input_short_circuits_without_calling_es(self, monkeypatch):
        called = {"n": 0}

        async def should_not_run(index, body, timeout):
            called["n"] += 1
            return {}

        monkeypatch.setattr(es_tool, "es_search", should_not_run)
        summaries, gap = run(
            elasticsearch_related_alerts(
                None, None, None, investigation_profile="network_threat"
            )
        )
        assert summaries == []
        assert gap is not None
        assert "nothing to correlate" in gap.reason
        assert called["n"] == 0

    def test_hours_reflected_in_range_filter(self, monkeypatch, real_related_suricata_response):
        capture: dict = {}
        patch_es(monkeypatch, result=real_related_suricata_response, capture=capture)
        run(
            elasticsearch_related_alerts(
                None,
                None,
                None,
                network=REAL_SURICATA_NETWORK,
                investigation_profile="network_threat",
                hours=6,
            )
        )
        filters = capture["body"]["query"]["bool"]["filter"]
        assert {"range": {"@timestamp": {"gte": "now-6h"}}} in filters


# ===========================================================================
# elasticsearch_related_alerts — Suricata path, failure paths
# ===========================================================================
class TestRelatedAlertsSuricataFailuresProduceGapsNotExceptions:
    def test_connection_error(self, monkeypatch):
        patch_es(monkeypatch, exc=httpx.ConnectError("connection refused"))
        summaries, gap = run(
            elasticsearch_related_alerts(
                None,
                None,
                None,
                network=REAL_SURICATA_NETWORK,
                investigation_profile="network_threat",
            )
        )
        assert summaries == []
        assert gap is not None
        assert gap.tool == "elasticsearch_related_alerts"
        assert "Cannot connect to Elasticsearch" in gap.reason

    def test_timeout_produces_gap(self, monkeypatch):
        async def slow(index, body, timeout):
            await asyncio.sleep(5)

        monkeypatch.setattr(es_tool, "es_search", slow)
        summaries, gap = run(
            elasticsearch_related_alerts(
                None,
                None,
                None,
                network=REAL_SURICATA_NETWORK,
                investigation_profile="network_threat",
                timeout=0.05,
            )
        )
        assert summaries == []
        assert "Timeout after 0.05s" in gap.reason
        assert gap.duration_ms is not None


# ===========================================================================
# elasticsearch_process_history — REAL captured response
# ===========================================================================
class TestProcessHistoryAgainstRealCapturedResponse:
    def test_no_gap_and_populated(self, monkeypatch, real_process_response):
        patch_es(monkeypatch, result=real_process_response)
        events, gap = run(elasticsearch_process_history(REAL_HOST, REAL_USER, hours=24))
        assert gap is None
        assert len(events) == 5

    def test_field_mapping_from_real_hit(self, monkeypatch, real_process_response):
        patch_es(monkeypatch, result=real_process_response)
        events, _ = run(elasticsearch_process_history(REAL_HOST, REAL_USER, hours=24))
        first = events[0]
        raw = real_process_response["hits"]["hits"][0]["_source"]
        assert first.name == raw["process"]["name"]
        assert first.executable == raw["process"]["executable"]
        assert first.command_line == raw["process"]["command_line"]
        assert first.pid == raw["process"]["pid"]
        assert first.entity_id == raw["process"]["entity_id"]
        assert first.parent_name == raw["process"]["parent"]["name"]
        assert first.parent_command_line == raw["process"]["parent"]["command_line"]
        assert first.user == raw["user"]["name"]

    def test_integrity_and_elevation_mapped_when_present(
        self, monkeypatch, real_process_response
    ):
        """Gap #2. Real fixture hit 0 has process.Ext.token populated
        (integrity_level_name='system', elevation_level='default') — same
        field pair alert_builder.py's _extract_process_from_event_data
        already reads for the alerting process itself."""
        patch_es(monkeypatch, result=real_process_response)
        events, _ = run(elasticsearch_process_history(REAL_HOST, REAL_USER, hours=24))
        raw = real_process_response["hits"]["hits"][0]["_source"]
        token = raw["process"]["Ext"]["token"]
        assert events[0].integrity_level == token["integrity_level_name"]
        assert events[0].elevation_level == token["elevation_level"]

    def test_integrity_and_elevation_none_when_absent(
        self, monkeypatch, real_process_response
    ):
        """Real fixture hits 2-4 have no process.Ext.token at all — must
        degrade to None, never raise."""
        patch_es(monkeypatch, result=real_process_response)
        events, _ = run(elasticsearch_process_history(REAL_HOST, REAL_USER, hours=24))
        raw_hits = real_process_response["hits"]["hits"]
        for i in (2, 3, 4):
            assert "token" not in raw_hits[i]["_source"]["process"].get("Ext", {})
            assert events[i].integrity_level is None
            assert events[i].elevation_level is None

    def test_fields_read_top_level_not_nested_under_event_data(
        self, monkeypatch, real_process_response
    ):
        """This index is standalone — unlike the alerts index, process fields
        live at top level, not under `event_data`. This guards against
        accidentally copy-pasting the alerts-index mapping."""
        raw = real_process_response["hits"]["hits"][0]["_source"]
        assert "event_data" not in raw
        assert "process" in raw

    def test_zero_hits_is_a_valid_empty_result(self, monkeypatch):
        patch_es(monkeypatch, result={"hits": {"hits": []}})
        events, gap = run(elasticsearch_process_history(REAL_HOST, REAL_USER, hours=24))
        assert gap is None
        assert events == []


# ===========================================================================
# elasticsearch_process_history — the query itself
# ===========================================================================
class TestProcessHistoryQueryConstruction:
    def test_index_and_size_and_sort(self, monkeypatch, real_process_response):
        capture: dict = {}
        patch_es(monkeypatch, result=real_process_response, capture=capture)
        run(elasticsearch_process_history(REAL_HOST, REAL_USER, hours=24))
        assert capture["index"] == ".ds-logs-endpoint.events.process-*"
        assert capture["body"]["size"] == 50
        assert capture["body"]["sort"] == [
            {"@timestamp": {"order": "desc", "unmapped_type": "date"}}
        ]

    def test_host_scoped_not_user_scoped(self, monkeypatch, real_process_response):
        """Architecture §6 tool 7: 'what other processes ran on this host' —
        host-scoped, not user-scoped. `user` is accepted for output-mapping
        parity but must not narrow the query."""
        capture: dict = {}
        patch_es(monkeypatch, result=real_process_response, capture=capture)
        run(elasticsearch_process_history(REAL_HOST, REAL_USER, hours=24))
        filters = capture["body"]["query"]["bool"]["filter"]
        assert {"term": {"host.name": "win-kvkmd51ggkq"}} in filters
        assert not any("user" in str(f) for f in filters)

    def test_hours_reflected_in_range_filter(self, monkeypatch, real_process_response):
        capture: dict = {}
        patch_es(monkeypatch, result=real_process_response, capture=capture)
        run(elasticsearch_process_history(REAL_HOST, REAL_USER, hours=6))
        filters = capture["body"]["query"]["bool"]["filter"]
        assert {"range": {"@timestamp": {"gte": "now-6h"}}} in filters

    def test_timeout_is_passed_through(self, monkeypatch, real_process_response):
        capture: dict = {}
        patch_es(monkeypatch, result=real_process_response, capture=capture)
        run(elasticsearch_process_history(REAL_HOST, REAL_USER, timeout=2.5))
        assert capture["timeout"] == 2.5

    def test_no_hostname_short_circuits_without_calling_es(self, monkeypatch):
        called = {"n": 0}

        async def should_not_run(index, body, timeout):
            called["n"] += 1
            return {}

        monkeypatch.setattr(es_tool, "es_search", should_not_run)
        events, gap = run(elasticsearch_process_history(None, REAL_USER))
        assert events == []
        assert gap is not None
        assert "No hostname" in gap.reason
        assert called["n"] == 0

    def test_empty_hostname_short_circuits(self, monkeypatch):
        called = {"n": 0}

        async def should_not_run(index, body, timeout):
            called["n"] += 1
            return {}

        monkeypatch.setattr(es_tool, "es_search", should_not_run)
        events, gap = run(elasticsearch_process_history(Host(hostname=""), None))
        assert events == []
        assert gap is not None
        assert called["n"] == 0


# ===========================================================================
# elasticsearch_process_history — failure paths
# ===========================================================================
class TestProcessHistoryFailuresProduceGapsNotExceptions:
    def test_connection_error(self, monkeypatch):
        patch_es(monkeypatch, exc=httpx.ConnectError("connection refused"))
        events, gap = run(elasticsearch_process_history(REAL_HOST, REAL_USER))
        assert events == []
        assert gap is not None
        assert gap.tool == "elasticsearch_process_history"
        assert "Cannot connect to Elasticsearch" in gap.reason

    def test_http_error_includes_status_and_body(self, monkeypatch):
        response = httpx.Response(
            500, text="internal error", request=httpx.Request("POST", "https://es/_search")
        )
        patch_es(
            monkeypatch,
            exc=httpx.HTTPStatusError("boom", request=response.request, response=response),
        )
        _, gap = run(elasticsearch_process_history(REAL_HOST, REAL_USER))
        assert "HTTP 500" in gap.reason
        assert "internal error" in gap.reason

    def test_timeout_produces_gap(self, monkeypatch):
        async def slow(index, body, timeout):
            await asyncio.sleep(5)

        monkeypatch.setattr(es_tool, "es_search", slow)
        events, gap = run(elasticsearch_process_history(REAL_HOST, REAL_USER, timeout=0.05))
        assert events == []
        assert "Timeout after 0.05s" in gap.reason
        assert gap.duration_ms is not None


# ===========================================================================
# ioc.* regression guard — synthetic, deliberately divergent from rule.uuid
# ===========================================================================
class TestIocFieldNeverRead:
    """CLAUDE.md: `ioc.*` is a custom development-time pipeline layered on top
    of Security Onion, never corroborating evidence, and must never be built
    on. The real fixture happens to have `ioc.rule.uuid == rule.uuid`, which
    would let a bug slip through unnoticed — this test constructs a response
    where they diverge, so a regression that starts reading `ioc.*` fails
    loudly."""

    def test_rule_uuid_ignores_diverging_ioc_block(self, monkeypatch):
        response = {
            "hits": {
                "hits": [
                    {
                        "_id": "synthetic1",
                        "_source": {
                            "@timestamp": "2026-08-13T00:00:00.000Z",
                            "event": {"severity": 4},
                            "rule": {
                                "name": "Real Rule",
                                "uuid": "real-uuid-from-rule-block",
                            },
                            "ioc": {
                                "rule": {"uuid": "decoy-uuid-from-ioc-block"},
                            },
                            "event_data": {
                                "host": {"name": "win-kvkmd51ggkq"},
                                "user": {"name": "Administrator"},
                            },
                        },
                    }
                ]
            }
        }
        patch_es(monkeypatch, result=response)
        summaries, _ = run(
            elasticsearch_related_alerts(
                REAL_HOST, REAL_USER, None, investigation_profile="endpoint_behavior", hours=24
            )
        )
        assert summaries[0].rule_uuid == "real-uuid-from-rule-block"
        assert summaries[0].rule_uuid != "decoy-uuid-from-ioc-block"
