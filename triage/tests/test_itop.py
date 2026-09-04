"""`itop_asset_lookup` — architecture §6 tool 5.

PROVENANCE: `tests/fixtures/itop_demo_real.json` holds ACTUAL captured
responses from the live iTop at `http://172.20.24.220:8080` on 2026-08-14 —
the stock community demo dataset (`Server1`, `Router1`), which is what this
deployment's `config.ITOP_URL` currently points at. This SUPERSEDES the
2026-08-08 capture against a different, now-gone instance (`PC::32`,
win-kvkmd51ggkq) — see `tools/itop.py`'s module docstring for the full
deployment-change note. Six real responses: hostname locate + finalclass
refetch for both a `Server` and a `NetworkDevice`, a genuine not-found, a
genuine asset_number-filter API error, and a genuine (empty) asset_number
locate — the tool was called against the real backend before any of these
tests were written or rewritten (implementation guide §2).

This deployment's iTop has NO network_zone, NO data_sensitivity, NO owner
attribute on any class, and no *demo* object carries an IP or a populated
`asset_number` — re-verified live 2026-08-14, same conclusion as before on a
different instance. Tests assert those are None/empty because that is the
verified truth today — see the module docstring of `tools/itop.py`.

**`Server::32` is not demo data.** It was created live on 2026-08-14
(`core/create` via the iTop MCP) specifically so `itop_asset_lookup`'s
asset_number-primary-match path has a real object to resolve against: `name`
is the real Elastic Agent hostname from a captured production alert
(`win-kvkmd51ggkq`) and `asset_number` is that alert's real
`event_data.host.id` UUID (`c8fc26bf-dc76-4dba-adbb-bf31640d9c9f`) — not
invented. `business_criticity`, `brand_id`, `osfamily_id`/`osversion_id`,
`serialnumber`, `cpu`/`ram` ARE invented (no source of truth for them existed)
but are valid FK references to real Brand/OSFamily/OSVersion/Location objects
already in this CMDB — see `TestAssetNumberPathWhenPopulated` below, which
uses this real object's real captured responses, not a synthetic stand-in.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from tools import itop as itop_mod
from tools.itop import ItopOqlValueError, _normalise_criticality, itop_asset_lookup

FIXTURE = Path(__file__).parent / "fixtures" / "itop_demo_real.json"
HOSTNAME = "Server1"
ROUTER_HOSTNAME = "Router1"
# The real object created for this deployment (module docstring): a real
# alert's hostname + real host.id UUID, so this DOES match live.
POPULATED_HOSTNAME = "win-kvkmd51ggkq"
POPULATED_HOST_UUID = "c8fc26bf-dc76-4dba-adbb-bf31640d9c9f"


@pytest.fixture(scope="module")
def real() -> dict:
    """REAL — captured live from iTop at 172.20.24.220:8080 on 2026-08-14."""
    return json.loads(FIXTURE.read_text())


def patch_itop(monkeypatch, responses=None, exc=None, capture=None, router=False):
    """Replace the iTop transport, dispatching on the queried class so the
    two-phase locate/refetch flow is exercised as it really runs.

    `router=True` serves the Router1/NetworkDevice fixtures instead of the
    Server1 ones, for the asset_type-priority tests.
    """
    hostname_key = "locate_by_hostname_router1" if router else "locate_by_hostname"
    refetch_key = "refetch_final_class_router1" if router else "refetch_final_class"

    async def fake_get(cls, oql, timeout, fields="*"):
        if capture is not None:
            capture.setdefault("calls", []).append({"class": cls, "oql": oql})
        if exc is not None:
            raise exc
        if cls == "PhysicalDevice":
            return responses.get("locate_by_asset_number", {"code": 0, "objects": {}})
        if cls == "FunctionalCI":
            return responses.get(hostname_key, {"code": 0, "objects": {}})
        return responses.get(refetch_key, {"code": 0, "objects": {}})

    monkeypatch.setattr(itop_mod, "_itop_get", fake_get)


def run(coro):
    return asyncio.run(coro)


class TestAgainstRealCapturedResponses:
    def test_hostname_locate_resolves_against_the_live_backend(self, monkeypatch, real):
        """One of two tests in this suite that skip mocking and hit the real,
        live iTop. No host_id given, so this proves the hostname path alone
        works end-to-end against the demo data, not just against a captured
        fixture."""
        context, gap = run(itop_asset_lookup(HOSTNAME, None))
        assert gap is None
        assert context.found is True
        assert context.matched_by == "hostname"
        assert context.hostname == HOSTNAME

    def test_asset_number_locate_resolves_against_the_live_backend(self, monkeypatch, real):
        """The other live, unmocked test. `Server::32` (module docstring) is a
        real object with a real, populated `asset_number` — this proves the
        PRIMARY join path actually works end-to-end today, not just that the
        code exists for when data eventually gets populated."""
        context, gap = run(itop_asset_lookup(POPULATED_HOSTNAME, POPULATED_HOST_UUID))
        assert gap is None
        assert context.found is True
        assert context.matched_by == "asset_number"
        assert context.asset_number == POPULATED_HOST_UUID
        assert context.criticality == "high"
        assert context.os_family == "Windows"
        assert context.os_version == "11"

    def test_full_field_set_after_final_class_refetch(self, monkeypatch, real):
        """REGRESSION GUARD for a bug the first live run caught (2026-08-08,
        against the old instance; still applies here).

        `output_fields: "*"` returns only the attributes of the class queried.
        Locating on FunctionalCI yields none of os_family/location/model_name;
        the refetch on `finalclass` is what completes the record.
        """
        patch_itop(monkeypatch, real)
        context, _ = run(itop_asset_lookup(HOSTNAME, None))
        assert context.itop_class == "Server"
        assert context.itop_id == "1"
        assert context.os_family == "vCenter Server"
        assert context.os_version == "2022"
        assert context.location == "Bordeaux"
        assert context.asset_type == "DL380"  # model_name fallback — no `type` on Server
        assert context.asset_number is None  # blank on every object in this instance

    def test_criticality_is_the_business_criticity_attribute(self, monkeypatch, real):
        """iTop spells it `business_criticity`. Observed on this instance:
        every sampled object (Server1-4, VM1-4, Router1) is `low`."""
        patch_itop(monkeypatch, real)
        context, _ = run(itop_asset_lookup(HOSTNAME, None))
        assert context.criticality == "low"

    def test_organization_and_status(self, monkeypatch, real):
        patch_itop(monkeypatch, real)
        context, _ = run(itop_asset_lookup(HOSTNAME, None))
        assert context.organization == "IT Department"
        assert context.status == "production"
        assert context.obsolete is False

    def test_fields_this_itop_does_not_have_are_none(self, monkeypatch, real):
        """Verified absent from every class in this instance. When custom
        fields are added later, THIS is the test that should change —
        deliberately."""
        patch_itop(monkeypatch, real)
        context, _ = run(itop_asset_lookup(HOSTNAME, None))
        assert context.network_zone is None
        assert context.data_sensitivity == []
        assert context.owner is None
        assert context.ip_addresses == []
        assert context.services == []

    def test_asset_type_prefers_networkdevicetype_name_over_model_name(self, monkeypatch, real):
        """Router1 has both `networkdevicetype_name` ("Router") and
        `model_name` ("Procurve 2450") — the more specific, class-native field
        must win."""
        patch_itop(monkeypatch, real, router=True)
        context, _ = run(itop_asset_lookup(ROUTER_HOSTNAME, None))
        assert context.itop_class == "NetworkDevice"
        assert context.asset_type == "Router"


class TestAssetNumberPathWhenPopulated:
    """REAL — `Server::32` (module docstring), captured 2026-08-14 via the
    tool's own `_itop_get` transport, under
    `locate_by_asset_number_populated` / `refetch_final_class_populated` in
    the fixture. Formerly synthetic (no populated object existed); superseded
    once `Server::32` was created, per this project's real-over-synthetic
    fixture discipline."""

    def test_asset_number_match_is_preferred_and_skips_hostname_query(self, monkeypatch, real):
        capture: dict = {}
        patch_itop(
            monkeypatch,
            {
                "locate_by_asset_number": real["locate_by_asset_number_populated"],
                "refetch_final_class": real["refetch_final_class_populated"],
            },
            capture=capture,
        )
        context, gap = run(itop_asset_lookup(POPULATED_HOSTNAME, POPULATED_HOST_UUID))
        assert gap is None
        assert context.matched_by == "asset_number"
        assert context.asset_number == POPULATED_HOST_UUID
        assert not any(c["class"] == "FunctionalCI" for c in capture["calls"])

    def test_refetch_failure_degrades_to_partial_object(self, monkeypatch, real):
        """A refetch failure must not lose the locate-phase result — partial
        data beats no data. The locate-phase response (real, from
        `PhysicalDevice`) already carries `asset_number` and
        `business_criticity` but not `osfamily_name` — see the "TWO THINGS..."
        note in `tools/itop.py`'s module docstring — so `os_family` staying
        `None` here is the expected real shape, not a simulated gap."""

        async def flaky(cls, oql, timeout, fields="*"):
            if cls == "PhysicalDevice":
                return real["locate_by_asset_number_populated"]
            raise httpx.ConnectError("refetch died")

        monkeypatch.setattr(itop_mod, "_itop_get", flaky)
        context, gap = run(itop_asset_lookup(POPULATED_HOSTNAME, POPULATED_HOST_UUID))
        assert context.found is True
        assert context.criticality == "high"
        assert context.os_family is None  # lost with the refetch, as expected
        assert gap is None


class TestQueryConstruction:
    def test_uuid_queried_on_physicaldevice_not_functionalci(self, monkeypatch, real):
        """`asset_number` is not a filterable attribute on FunctionalCI — the
        real API rejects it. It exists only on PhysicalDevice and its
        subclasses."""
        capture: dict = {}
        patch_itop(monkeypatch, real, capture=capture)
        run(itop_asset_lookup(HOSTNAME, POPULATED_HOST_UUID))
        first = capture["calls"][0]
        assert first["class"] == "PhysicalDevice"
        assert "asset_number" in first["oql"]

    def test_hostname_queried_on_broadest_class(self, monkeypatch, real):
        """FunctionalCI deliberately — a VirtualMachine has no asset_number at
        all (VMs are not PhysicalDevice), so the hostname path is what covers
        them and must not be narrowed."""
        capture: dict = {}
        patch_itop(monkeypatch, real, capture=capture)
        run(itop_asset_lookup(HOSTNAME, None))
        assert capture["calls"][0]["class"] == "FunctionalCI"

    def test_uuid_path_skips_the_hostname_query_entirely_when_no_match(self, monkeypatch, real):
        """`real["locate_by_asset_number"]` is the genuine empty-result capture
        (module docstring): most demo objects still have no asset_number, so
        this documents that when the PhysicalDevice locate comes back empty,
        the code still falls through to the hostname query — it does not skip
        it."""
        capture: dict = {}
        patch_itop(monkeypatch, real, capture=capture)
        run(itop_asset_lookup(HOSTNAME, POPULATED_HOST_UUID))
        assert any(c["class"] == "FunctionalCI" for c in capture["calls"])


class TestOqlInjectionIsRejected:
    """Hostnames come from Security Onion telemetry and are attacker
    influenceable, and they are interpolated into an OQL string."""

    @pytest.mark.parametrize(
        "hostname",
        [
            'x" OR 1=1 OR name="',
            "host'; SELECT Person WHERE 1=1",
            'win-kvkmd51ggkq" UNION SELECT Person WHERE name LIKE "%',
            "host\nname",
            "a" * 300,
        ],
    )
    def test_unsafe_hostname_produces_gap_not_a_query(self, monkeypatch, hostname):
        capture: dict = {}
        patch_itop(monkeypatch, {}, capture=capture)
        context, gap = run(itop_asset_lookup(hostname))
        assert context.found is False
        assert "Unsafe lookup value" in gap.reason
        assert capture.get("calls") is None

    def test_legitimate_hostname_forms_are_accepted(self, monkeypatch, real):
        patch_itop(monkeypatch, real)
        for hostname in ("win-kvkmd51ggkq", "HOST.corp.example.com", "srv_01".replace("_", "-")):
            context, _ = run(itop_asset_lookup(hostname))
            assert context.found is True

    def test_unsafe_host_id_also_rejected(self, monkeypatch):
        capture: dict = {}
        patch_itop(monkeypatch, {}, capture=capture)
        _, gap = run(itop_asset_lookup(None, 'uuid" OR "1"="1'))
        assert "Unsafe lookup value" in gap.reason
        assert capture.get("calls") is None


class TestFailuresProduceGapsNotExceptions:
    def test_asset_absent_is_a_valid_result(self, monkeypatch, real):
        """Real captured not-found response. Distinguishable from a backend
        failure — architecture §2 requirement 4."""
        patch_itop(monkeypatch, {"locate_by_hostname": real["not_found"]})
        context, gap = run(itop_asset_lookup("does-not-exist-host"))
        assert context.found is False
        assert "No CMDB object matched" in gap.reason
        assert "timeout" not in gap.reason.lower()

    def test_itop_application_error_is_surfaced(self, monkeypatch, real):
        """iTop returns HTTP 200 with a non-zero `code` for API errors — it
        does not use HTTP status codes. Real captured error response; the
        exact wrapper text changed on this iTop build (module docstring) but
        "Unknown filter code" is still a substring either way."""
        patch_itop(monkeypatch, {"locate_by_hostname": real["error_unknown_filter"]})
        context, gap = run(itop_asset_lookup(HOSTNAME))
        assert context.found is False
        assert "iTop error 100" in gap.reason
        assert "Unknown filter code" in gap.reason

    def test_connection_error(self, monkeypatch):
        patch_itop(monkeypatch, exc=httpx.ConnectError("refused"))
        context, gap = run(itop_asset_lookup(HOSTNAME))
        assert context.found is False
        assert "Cannot connect to iTop" in gap.reason

    def test_http_error(self, monkeypatch):
        response = httpx.Response(
            401, text="auth failed", request=httpx.Request("POST", "http://itop/rest")
        )
        patch_itop(
            monkeypatch,
            exc=httpx.HTTPStatusError("x", request=response.request, response=response),
        )
        _, gap = run(itop_asset_lookup(HOSTNAME))
        assert "HTTP 401 from iTop" in gap.reason
        assert "auth failed" in gap.reason

    def test_timeout(self, monkeypatch):
        async def slow(cls, oql, timeout, fields="*"):
            await asyncio.sleep(5)

        monkeypatch.setattr(itop_mod, "_itop_get", slow)
        context, gap = run(itop_asset_lookup(HOSTNAME, timeout=0.05))
        assert context.found is False
        assert "Timeout after 0.05s" in gap.reason

    def test_no_lookup_key_at_all(self, monkeypatch):
        capture: dict = {}
        patch_itop(monkeypatch, {}, capture=capture)
        context, gap = run(itop_asset_lookup(None, None))
        assert context.found is False
        assert "neither a hostname nor a host id" in gap.reason
        assert capture.get("calls") is None


class TestCriticalityGapSemantics:
    def test_found_without_criticality_still_produces_a_gap(self, monkeypatch):
        """Architecture §17 calls unpopulated iTop the single biggest deployment
        risk. A found-but-blank asset silently degrades impact scoring to a
        constant, so it must NOT look like a fully successful lookup."""
        blank = {
            "code": 0,
            "objects": {
                "Server::99": {
                    "class": "Server",
                    "key": "99",
                    "fields": {"name": "x", "finalclass": "Server", "business_criticity": ""},
                }
            },
        }
        patch_itop(monkeypatch, {"locate_by_hostname": blank, "refetch_final_class": blank})
        context, gap = run(itop_asset_lookup("x"))
        assert context.found is True
        assert context.criticality is None
        assert gap is not None
        assert "no business_criticity" in gap.reason

    @pytest.mark.parametrize(
        "raw,expected",
        [("high", "high"), ("MEDIUM", "medium"), ("  low ", "low"), ("", None), (None, None)],
    )
    def test_criticality_normalisation(self, raw, expected):
        assert _normalise_criticality(raw) == expected

    def test_unknown_criticality_passes_through_rather_than_being_coerced(self, caplog):
        """A new tier appearing in iTop is something to find out about, not to
        silently flatten into a known value."""
        assert _normalise_criticality("catastrophic") == "catastrophic"
