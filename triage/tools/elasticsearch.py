"""`elasticsearch_related_alerts` and `elasticsearch_process_history` — architecture §6
tools 6 and 7. Together these are the ENTIRE set of Elasticsearch evidence Stage 1
gathers, alongside `tools/detection_rules.py::detection_rule_lookup` (a third ES call,
against `so-detection`, covered in that file — this docstring is scoped to the two
tools defined here).

- `elasticsearch_related_alerts` answers "what OTHER ALERTS fired near this one" —
  same host/user/IOCs in the last N hours. Feeds Stage 5's velocity multiplier and
  Stage 3's kill-chain reasoning.
- `elasticsearch_process_history` answers "what OTHER PROCESSES ran on this host" —
  raw endpoint telemetry, not alerts. Feeds Stage 3's behavioral/process-chain
  reasoning. Sigma-only: gated in `nodes/gather.py` to fire only when
  `alert.event_dataset == "endpoint.events.process"`, and structurally cannot apply
  to a Suricata alert regardless — Suricata alerts carry no `host.hostname`
  (confirmed on every real captured Suricata doc; see also `tools/itop.py`'s docstring
  on the same structural gap for asset lookup). For a Suricata-sourced alert this
  always returns `([], Gap("No hostname on the alert"))` — a real, expected, honest
  gap, not a bug.

**`elasticsearch_related_alerts` is engine-branched (fixed 2026-08-21, gap #17).**
Two independent, real backends, selected by `investigation_profile` (set once in
`alert_builder.py`, per `CanonicalAlert.investigation_profile` — see
`schemas/alert.py`'s `InvestigationProfile` docstring, which already named this
dispatch as the intended design):

- `investigation_profile == "endpoint_behavior"` (Sigma) -> `_related_alerts_sigma`,
  querying `config.ES_ALERTS_INDEX` (`logs-detections.alerts-so*`) by
  `event_data.host.name` / `event_data.user.name` / `event_data.related.{ip,hash}`.
  Unchanged from the original implementation; see the field-presence probe below.
- `investigation_profile == "network_threat"` (Suricata) -> `_related_alerts_suricata`,
  querying `config.ES_SURICATA_ALERTS_INDEX` (`logs-suricata.alerts-so*`) by
  `network.community_id` / `source.ip` / `destination.ip` — all three tier-1
  live-confirmed 100%-populated across 254k+ real Suricata alert docs (2026-08-21
  field census). Suricata alerts have no `event_data` wrapper at all — the fields
  the Sigma path reads simply don't exist on this document shape, which is why the
  original single-index, single-field-set implementation silently returned `[]` for
  every Suricata alert (queries `ES_ALERTS_INDEX`, which is 100% Sigma; even had it
  queried the right index, `event_data.host.name` etc. don't exist there either) with
  no `Gap` logged — a real bug, not just the (separate, workflow-level) ingestion gap
  documented in CLAUDE.md's Suricata section.
- Any other profile (`malicious_file`, `generic`) -> no verified correlation query
  exists yet for that document shape (no live YARA/Strelka alert has ever fired in
  this deployment to verify a query against — implementation guide §0.1). Returns an
  explicit `Gap` rather than silently running the Sigma-shaped query and getting a
  meaningless empty result, which is what happened before this fix.

Do not add a third index/field-set to `elasticsearch_related_alerts` on inference
alone (e.g. for `malicious_file`) — verify a real alert of that shape first, per
implementation guide §2's discipline, the same way the Suricata path above was
built from a live field census, not guessed from ECS documentation.

**`ioc.*` is never read here.** The Sigma alert document real fixture has an
`ioc.rule.uuid` that looks like a tempting shortcut for `rule.uuid` — per CLAUDE.md's
ground-truth hierarchy, `ioc.*` comes from a custom development-time pipeline layered
on top of Security Onion, is not corroborating evidence, and must never be built on.
`rule.uuid` (top level) is the correct field for both engines.

Sigma-path observable/IOC correlation matches against the ECS entity-rollup fields
`event_data.related.ip` and `event_data.related.hash` — Elastic Agent's own
aggregation of every IP / hash seen on a process event, populated independently of
which specific sub-field (process hash, DNS answer, network connection, ...) they
came from. Live field-presence probe against the real alerts index on 2026-08-13
(`_source` filtered `exists` query, `size=1`, count via `hits.total.value`):

    event_data.related.ip                4708 of ~7700 docs populated
    event_data.related.hash               332 of ~7700 docs populated
    event_data.destination.ip                0 docs populated
    event_data.network.protocol              0 docs populated
    event_data.dns.question.name             0 docs populated
    event_data.url.{original,domain,full}    0 docs populated (all three)

`external_ips` and file hashes are therefore matched against `related.ip` /
`related.hash` on the Sigma path. `domains` and `urls` remain UNMATCHED on BOTH
paths, deliberately — not a guess deferred for later, but live-confirmed absence:
0% of the Sigma alerts index AND 0% of the 254k+ real Suricata alerts index (checked
both ECS names like `dns.question.name`/`http.request.method` and Suricata-native
names like `dns.rrname`/`http.hostname`/`tls.sni`, 2026-08-21 field census) carry any
DNS/HTTP/TLS field — this Suricata sensor is configured alert-only, not full EVE
firehose (gap #14), so no domain/URL/DNS evidence exists anywhere in this deployment
today regardless of engine. **Trap found during that census, worth restating here
since it is exactly the shape of field this file's correlation logic would reach
for**: `dns.query_name` IS populated on the Suricata alerts index (100% of docs) but
is NOT real DNS data — sampled directly, it is the firing rule's own raw `content:`
match bytes, misrouted into a DNS-shaped field by the ingest pipeline. It appeared on
a doc whose rule is an HTTP backdoor signature with zero DNS component. Do not wire
this field into any future domain/URL correlation clause.

Both functions NEVER RAISE. Each returns `(list[Model], Gap | None)`:
- success (including zero hits) -> `(list, None)`
- nothing to query on (no correlation input given, or unsupported engine) -> `([], Gap)`, ES never called
- backend failure / timeout -> `([], Gap)` with the transport error reason
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import config
from schemas import AlertSummary, Gap, Host, Network, Observables, ProcessEvent, User
from tools.es_client import describe_http_error, es_search

logger = logging.getLogger(__name__)

TOOL_NAME_RELATED = "elasticsearch_related_alerts"
TOOL_NAME_PROCESS = "elasticsearch_process_history"
SOURCE = "elasticsearch"

RESULT_CAP = 50

# investigation_profile values with a verified, wired correlation query.
_PROFILE_SIGMA = "endpoint_behavior"
_PROFILE_SURICATA = "network_threat"


def _observable_should_clauses(observables: Observables | None) -> list[dict[str, Any]]:
    """`should` clauses correlating this alert's observables against other alert
    documents' ECS entity-rollup fields.

    `event_data.related.ip` and `event_data.related.hash` are used because they
    are the fields live-confirmed populated in this deployment (see module
    docstring for the field-presence probe). `related.hash` is a single flat
    list mixing algorithms (sha256/md5/imphash together on the same document),
    so all hash values across every `HashBundle` algorithm are combined into one
    `terms` clause rather than one clause per algorithm.

    `domains` / `urls` produce no clause — no live-verified field carries them
    yet (module docstring). An empty `terms` list is skipped entirely rather
    than sent, since it's a valid-but-useless ES query.
    """
    if observables is None:
        return []
    clauses: list[dict[str, Any]] = []
    if observables.external_ips:
        clauses.append({"terms": {"event_data.related.ip": observables.external_ips}})
    all_hashes = [
        *observables.hashes.md5,
        *observables.hashes.sha1,
        *observables.hashes.sha256,
        *observables.hashes.sha512,
    ]
    if all_hashes:
        clauses.append({"terms": {"event_data.related.hash": all_hashes}})
    return clauses


async def elasticsearch_related_alerts(
    host: Host | None,
    user: User | None,
    observables: Observables | None,
    network: Network | None = None,
    investigation_profile: str = "generic",
    hours: int = 24,
    timeout: float | None = None,
) -> tuple[list[AlertSummary], Gap | None]:
    """Other alerts correlating with this one in the last `hours` hours.

    Feeds Stage 5's velocity multiplier and Stage 3's kill-chain hypothesis
    (architecture §6 tool 6). Dispatches on `investigation_profile` — see the
    module docstring for why this can't be one query against one index for
    every engine. Callers (`nodes/gather.py`) always pass
    `alert.investigation_profile` explicitly; the "generic" default here only
    matters for a caller that omits it, which correctly produces a Gap rather
    than silently running the wrong query.
    """
    timeout = timeout if timeout is not None else config.STAGE_1_TOOL_TIMEOUT_ES
    started = time.monotonic()

    if investigation_profile == _PROFILE_SURICATA:
        return await _related_alerts_suricata(network, observables, hours, timeout, started)
    if investigation_profile == _PROFILE_SIGMA:
        return await _related_alerts_sigma(host, user, observables, hours, timeout, started)

    return [], Gap(
        source=SOURCE,
        tool=TOOL_NAME_RELATED,
        reason=(
            f"No verified alert-correlation query exists yet for "
            f"investigation_profile={investigation_profile!r} — only {_PROFILE_SIGMA!r} "
            f"(Sigma) and {_PROFILE_SURICATA!r} (Suricata) are wired. See implementation "
            "guide §0.1: no live YARA/Strelka alert has ever fired to verify a query "
            "against for 'malicious_file'."
        ),
        duration_ms=int((time.monotonic() - started) * 1000),
    )


async def _related_alerts_sigma(
    host: Host | None,
    user: User | None,
    observables: Observables | None,
    hours: int,
    timeout: float,
    started: float,
) -> tuple[list[AlertSummary], Gap | None]:
    """Sigma path — unchanged from the original implementation. Queries
    `config.ES_ALERTS_INDEX`, correlating via the `event_data.*` wrapper every
    Sigma alert document carries. See module docstring for the field-presence
    probe backing `event_data.related.{ip,hash}`."""

    def elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    should: list[dict[str, Any]] = []
    if host and host.hostname:
        should.append({"term": {"event_data.host.name": host.hostname}})
    if user and user.name:
        should.append({"term": {"event_data.user.name": user.name}})
    should.extend(_observable_should_clauses(observables))

    if not should:
        return [], Gap(
            source=SOURCE,
            tool=TOOL_NAME_RELATED,
            reason="No host, user, or observable hashes on the alert — nothing to correlate against",
            duration_ms=elapsed_ms(),
        )

    body = {
        "size": RESULT_CAP,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": f"now-{hours}h"}}}],
                "should": should,
                "minimum_should_match": 1,
            }
        },
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
    }

    try:
        payload = await asyncio.wait_for(
            es_search(config.ES_ALERTS_INDEX, body, timeout=timeout), timeout=timeout
        )
    except asyncio.TimeoutError:
        logger.warning("%s timed out after %.1fs", TOOL_NAME_RELATED, timeout)
        return [], Gap(
            source=SOURCE,
            tool=TOOL_NAME_RELATED,
            reason=f"Timeout after {timeout}s querying {config.ES_ALERTS_INDEX}",
            duration_ms=elapsed_ms(),
        )
    except Exception as exc:  # noqa: BLE001 — a tool must never raise into gather
        logger.warning("%s failed: %s", TOOL_NAME_RELATED, exc)
        return [], Gap(
            source=SOURCE,
            tool=TOOL_NAME_RELATED,
            reason=describe_http_error(exc),
            duration_ms=elapsed_ms(),
        )

    hits = (payload.get("hits") or {}).get("hits") or []
    summaries: list[AlertSummary] = []
    for hit in hits:
        source = hit.get("_source") or {}
        event = source.get("event") or {}
        rule = source.get("rule") or {}
        event_data = source.get("event_data") or {}
        hit_host = event_data.get("host") or {}
        hit_user = event_data.get("user") or {}
        summaries.append(
            AlertSummary(
                timestamp=source.get("@timestamp"),
                rule_name=rule.get("name") or "",
                rule_uuid=rule.get("uuid"),
                severity=event.get("severity"),
                host=hit_host.get("name"),
                user=hit_user.get("name"),
                alert_id=hit.get("_id"),
            )
        )
    return summaries, None


async def _related_alerts_suricata(
    network: Network | None,
    observables: Observables | None,
    hours: int,
    timeout: float,
    started: float,
) -> tuple[list[AlertSummary], Gap | None]:
    """Suricata path (gap #17, added 2026-08-21). Queries
    `config.ES_SURICATA_ALERTS_INDEX`, correlating via `network.community_id`
    and `source.ip`/`destination.ip` — Suricata alert documents have no
    `event_data` wrapper and no `host`/`user` concept at all (confirmed on
    every real captured Suricata doc), so the Sigma path's fields cannot
    apply here even pointed at the right index.

    `community_id` matching a document will always include the triggering
    alert itself (it's a bidirectional flow hash, and the alert that
    prompted this call is indexed in the same stream) — same as the Sigma
    path never excludes the calling alert by `host`/`user` either. Not
    treated as a bug; "this exact flow has alerted N times" is itself a
    useful signal, not noise to filter out.
    """

    def elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    should: list[dict[str, Any]] = []
    if network and network.community_id:
        should.append({"term": {"network.community_id": network.community_id}})
    if network and network.src_ip:
        should.append({"term": {"source.ip": network.src_ip}})
    if network and network.dst_ip:
        should.append({"term": {"destination.ip": network.dst_ip}})
    if observables and observables.external_ips:
        should.append({"terms": {"source.ip": observables.external_ips}})
        should.append({"terms": {"destination.ip": observables.external_ips}})

    if not should:
        return [], Gap(
            source=SOURCE,
            tool=TOOL_NAME_RELATED,
            reason=(
                "No community_id, source/destination IP, or IOC IPs on the alert — "
                "nothing to correlate against in logs-suricata.alerts-so*"
            ),
            duration_ms=elapsed_ms(),
        )

    body = {
        "size": RESULT_CAP,
        "query": {
            "bool": {
                "filter": [{"range": {"@timestamp": {"gte": f"now-{hours}h"}}}],
                "should": should,
                "minimum_should_match": 1,
            }
        },
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
    }

    try:
        payload = await asyncio.wait_for(
            es_search(config.ES_SURICATA_ALERTS_INDEX, body, timeout=timeout), timeout=timeout
        )
    except asyncio.TimeoutError:
        logger.warning("%s (suricata) timed out after %.1fs", TOOL_NAME_RELATED, timeout)
        return [], Gap(
            source=SOURCE,
            tool=TOOL_NAME_RELATED,
            reason=f"Timeout after {timeout}s querying {config.ES_SURICATA_ALERTS_INDEX}",
            duration_ms=elapsed_ms(),
        )
    except Exception as exc:  # noqa: BLE001 — a tool must never raise into gather
        logger.warning("%s (suricata) failed: %s", TOOL_NAME_RELATED, exc)
        return [], Gap(
            source=SOURCE,
            tool=TOOL_NAME_RELATED,
            reason=describe_http_error(exc),
            duration_ms=elapsed_ms(),
        )

    hits = (payload.get("hits") or {}).get("hits") or []
    summaries: list[AlertSummary] = []
    for hit in hits:
        source = hit.get("_source") or {}
        event = source.get("event") or {}
        rule = source.get("rule") or {}
        summaries.append(
            AlertSummary(
                timestamp=source.get("@timestamp"),
                rule_name=rule.get("name") or "",
                rule_uuid=rule.get("uuid"),
                severity=event.get("severity"),
                host=None,  # Suricata alerts carry no host/user concept
                user=None,
                alert_id=hit.get("_id"),
            )
        )
    return summaries, None


async def elasticsearch_process_history(
    host: Host | None,
    user: User | None,
    hours: int = 24,
    timeout: float | None = None,
) -> tuple[list[ProcessEvent], Gap | None]:
    """Other processes that ran on the same host in the last `hours` hours.

    Feeds Stage 3's behavioral / process-chain reasoning (architecture §6 tool
    7). Host-scoped, not user-scoped — "what else ran on this host" per the
    architecture doc's own framing; `user` is accepted for output mapping
    parity with the Stage 1 call signature but is not used to filter.

    Whether to call this at all for a given alert (architecture §6 tool 7:
    "only for Sigma alerts on `endpoint.events.process` dataset") is a decision
    for `nodes/gather.py`, which has `alert.event_dataset` to decide with —
    this tool has no dataset parameter and always queries when given a host.
    """
    timeout = timeout if timeout is not None else config.STAGE_1_TOOL_TIMEOUT_ES
    started = time.monotonic()

    def elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    if not host or not host.hostname:
        return [], Gap(
            source=SOURCE,
            tool=TOOL_NAME_PROCESS,
            reason="No hostname on the alert — nothing to query",
            duration_ms=elapsed_ms(),
        )

    body = {
        "size": RESULT_CAP,
        "query": {
            "bool": {
                "filter": [
                    {"term": {"host.name": host.hostname}},
                    {"range": {"@timestamp": {"gte": f"now-{hours}h"}}},
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc", "unmapped_type": "date"}}],
    }

    try:
        payload = await asyncio.wait_for(
            es_search(config.ES_PROCESS_INDEX, body, timeout=timeout), timeout=timeout
        )
    except asyncio.TimeoutError:
        logger.warning("%s timed out after %.1fs", TOOL_NAME_PROCESS, timeout)
        return [], Gap(
            source=SOURCE,
            tool=TOOL_NAME_PROCESS,
            reason=f"Timeout after {timeout}s querying {config.ES_PROCESS_INDEX}",
            duration_ms=elapsed_ms(),
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("%s failed: %s", TOOL_NAME_PROCESS, exc)
        return [], Gap(
            source=SOURCE,
            tool=TOOL_NAME_PROCESS,
            reason=describe_http_error(exc),
            duration_ms=elapsed_ms(),
        )

    hits = (payload.get("hits") or {}).get("hits") or []
    events: list[ProcessEvent] = []
    for hit in hits:
        source = hit.get("_source") or {}
        process = source.get("process") or {}
        parent = process.get("parent") or {}
        hit_user = source.get("user") or {}
        token = ((process.get("Ext") or {}).get("token")) or {}
        events.append(
            ProcessEvent(
                timestamp=source.get("@timestamp"),
                name=process.get("name"),
                executable=process.get("executable"),
                command_line=process.get("command_line"),
                pid=process.get("pid"),
                parent_name=parent.get("name"),
                parent_command_line=parent.get("command_line"),
                entity_id=process.get("entity_id"),
                user=hit_user.get("name"),
                integrity_level=token.get("integrity_level_name"),
                elevation_level=token.get("elevation_level"),
            )
        )
    return events, None
