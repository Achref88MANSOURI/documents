"""`opencti_observable_enrichment` — a deployment-added Stage-1 tool, NOT one
of architecture v4 §6's original 7. See CLAUDE.md "Deployment-specific
decisions: OpenCTI".

Queries OpenCTI's GraphQL API directly for an observable's threat-graph
context: is it a known indicator, and what is it related to (malware,
intrusion-set, threat-actor, campaign, via `stixCoreRelationships`).

DISTINCT FROM the OpenCTI Cortex analyzer (`OpenCTI_v6_SearchExactObservable_
2_0`), whose taxonomy rows already arrive through
`tools/thehive.py::get_full_alert_with_analysis` and are structured into
`CortexResult` alongside VirusTotal's. That path answers "did the SOC's own
Cortex pipeline flag this" from a pre-run analyzer job. This tool answers a
different question — "what does OpenCTI's own graph say this observable
relates to" — via a live GraphQL query, and both exist deliberately: neither
replaces the other.

VERIFIED AGAINST THE LIVE BACKEND 2026-08-13 — OpenCTI GraphQL 7.260318.0 at
`http://172.20.24.222:8080/graphql`.

A CREDENTIAL BUG WAS FOUND AND FIXED THE SAME DAY: the token stored in
`.mcp.json` (`lgrn_octi_tkn_...`) was missing a leading `f` and returns
`AUTH_REQUIRED` on every call. The corrected token (`flgrn_octi_tkn_...`) is
what `OPENCTI_TOKEN` in `.env` and `config.py` now carry.

THE EXACT-MATCH FILTER SHAPE, confirmed live:

    query($filters: FilterGroup) {
      stixCyberObservables(filters: $filters, first: N) { edges { node { ... } } }
    }
    filters = {"mode": "or", "filters": [{"key": "value", "values": [...]}], "filterGroups": []}

Batching multiple values into one `values` list in a single call is confirmed
working and returns only the genuine matches (verified with a 4-value batch —
2 real hits, 2 non-matches — returning exactly the 2 hits). None of this
deployment's own alert observables (the xordump URL, its sha256/imphash
hashes, `github.com`) exist in this OpenCTI instance's data — expected, since
they are a locally-generated test artifact, not a public IOC. The "found" path
was verified against real threat-feed indicators already in this instance
(`w8p3k.com`, `yezi.haoyun.bar`, `u85.ehlony.com` — domains from a recent OSINT
feed import), the "not found" path against the alert's own sha256 hash.

`stixCoreRelationships.to` uses inline fragments (`... on Malware { ... }`)
because `to` is a STIX-core union type; an unmatched fragment (e.g. the
relationship target is another Indicator, not a Malware/IntrusionSet/
ThreatActor/Campaign) resolves to `{}` rather than erroring — handled by
treating an empty `to` as "no attributable entity", not a Gap.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import httpx

import config
from schemas import Gap, Observables, OpenCTIEnrichment, OpenCTIRelation
from tools.thehive import _entity_values  # noqa: F401 — deliberate cross-module
# reuse: same "flatten an alert's IOCs into a match-value list" logic
# tools/thehive.py::search_open_cases_by_entities already needs. Not
# duplicated here; see CLAUDE.md "OpenCTI" entry.

logger = logging.getLogger(__name__)

SOURCE = "opencti"
TOOL_NAME = "opencti_observable_enrichment"

# Mirrors tools/thehive.py's MAX_ENTITY_VALUES — a very long value list makes
# the query slower and risks a request-size rejection.
MAX_ENTITY_VALUES = 50
MAX_RELATIONS_PER_OBSERVABLE = 10

_QUERY = """
query Enrich($filters: FilterGroup) {
  stixCyberObservables(filters: $filters, first: %d) {
    edges { node {
      observable_value
      entity_type
      x_opencti_score
      objectLabel { value }
      objectMarking { definition }
      indicators { edges { node { name } } }
      stixCoreRelationships(first: %d) { edges { node {
        relationship_type
        to {
          ... on Malware { name entity_type }
          ... on IntrusionSet { name entity_type }
          ... on ThreatActor { name entity_type }
          ... on Campaign { name entity_type }
        }
      } } }
    } }
  }
}
""" % (MAX_ENTITY_VALUES, MAX_RELATIONS_PER_OBSERVABLE)


def _describe_error(exc: Exception) -> str:
    if isinstance(exc, httpx.HTTPStatusError):
        body = (exc.response.text or "")[:250].replace("\n", " ")
        return f"HTTP {exc.response.status_code} from OpenCTI: {body}"
    if isinstance(exc, httpx.ConnectError):
        return f"Cannot connect to OpenCTI at {config.OPENCTI_URL}: {exc}"
    if isinstance(exc, httpx.ReadTimeout):
        return f"OpenCTI read timeout: {exc}"
    return f"{type(exc).__name__}: {exc}"


def _node_to_enrichment(node: dict) -> OpenCTIEnrichment:
    relations = []
    for edge in (node.get("stixCoreRelationships") or {}).get("edges", []) or []:
        rel = edge.get("node") or {}
        to = rel.get("to") or {}
        if not to:
            # An empty `to` means the relationship target didn't match any of
            # the inline fragments above (e.g. it's another Indicator) — real
            # data, not a Gap; the relationship exists, just not to an
            # attributable entity this tool cares about.
            continue
        relations.append(OpenCTIRelation(
            relationship_type=rel.get("relationship_type") or "",
            related_entity_type=to.get("entity_type"),
            related_entity_name=to.get("name"),
        ))
    return OpenCTIEnrichment(
        observable=node.get("observable_value") or "",
        found=True,
        entity_type=node.get("entity_type"),
        indicator_names=[
            e["node"]["name"]
            for e in (node.get("indicators") or {}).get("edges", []) or []
            if e.get("node", {}).get("name")
        ],
        opencti_score=node.get("x_opencti_score"),
        labels=[
            e["value"] for e in node.get("objectLabel") or [] if e.get("value")
        ],
        marking=[
            e["definition"] for e in node.get("objectMarking") or [] if e.get("definition")
        ],
        relations=relations,
    )


async def _query(filters: dict, timeout: float) -> Any:
    """POST to OpenCTI's GraphQL endpoint. Raises on transport or HTTP error,
    or on a GraphQL-level error (200 status, `errors` key set — e.g. the
    AUTH_REQUIRED shape a bad token returns)."""
    headers = {
        "Authorization": f"Bearer {config.OPENCTI_TOKEN}",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(
            f"{config.OPENCTI_URL}/graphql",
            headers=headers,
            json={"query": _QUERY, "variables": {"filters": filters}},
        )
        response.raise_for_status()
        payload = response.json()
    if payload.get("errors"):
        messages = "; ".join(
            e.get("message", "unknown error") for e in payload["errors"][:3]
        )
        raise httpx.HTTPStatusError(
            f"GraphQL error: {messages}",
            request=response.request,
            response=response,
        )
    return payload.get("data", {}).get("stixCyberObservables", {}).get("edges", []) or []


async def opencti_observable_enrichment(
    observables: Observables | None, timeout: float | None = None
) -> tuple[list[OpenCTIEnrichment], Gap | None]:
    """Look up every IOC on the alert against OpenCTI's threat graph in one
    batched query.

    NEVER RAISES. Returns `(enrichments, Gap | None)`. Returns ONE entry per
    queried value, `found=True` for values OpenCTI has a record of and
    `found=False` for values it was checked against and does not — both are
    real answers, not gaps. A Gap means the query itself could not be run.
    """
    timeout = timeout if timeout is not None else config.STAGE_1_TOOL_TIMEOUT_OPENCTI
    started = time.monotonic()

    def gap(reason: str) -> Gap:
        return Gap(
            source=SOURCE,
            tool=TOOL_NAME,
            reason=reason,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    values = _entity_values(observables, None, None)[:MAX_ENTITY_VALUES]
    if not values:
        return [], gap("Alert carried no observables to check against OpenCTI")

    filters = {"mode": "or", "filters": [{"key": "value", "values": values}], "filterGroups": []}

    try:
        edges = await asyncio.wait_for(_query(filters, timeout), timeout=timeout)
    except asyncio.TimeoutError:
        return [], gap(f"Timeout after {timeout}s querying OpenCTI")
    except Exception as exc:  # noqa: BLE001 — a tool must never raise into gather
        logger.warning("opencti_observable_enrichment failed: %s", exc)
        return [], gap(_describe_error(exc))

    found_by_value = {}
    for edge in edges:
        node = edge.get("node") if isinstance(edge, dict) else None
        if not isinstance(node, dict) or not node.get("observable_value"):
            continue
        found_by_value[node["observable_value"]] = _node_to_enrichment(node)

    results = [
        found_by_value.get(v) or OpenCTIEnrichment(observable=v, found=False)
        for v in values
    ]
    return results, None
