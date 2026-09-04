"""`itop_asset_lookup` — architecture §6 tool 5, §13.

Resolves the alert's host to a CMDB asset and returns its business context.
Feeds the `impact` dimension of architecture §10's scoring formula.

**DEPLOYMENT CHANGE 2026-08-14: this is a different iTop instance than the one
this tool was originally verified against.** The 2026-08-08 verification was
against `http://172.20.24.223/itop` (`PC::32` / `win-kvkmd51ggkq`, a real host).
That instance is gone. The currently configured backend
(`config.ITOP_URL` = `http://172.20.24.220:8080`, auth is username+password —
`ITOP_USER`/`ITOP_PWD`, not an API key) is the **stock iTop community demo
dataset**: `Server1`-`4`, `VM1`-`4`, `ESX1`-`3` (Hypervisor), `Router1`/
`Switch1` (NetworkDevice), `Cluster1`/`2` (Farm), plus software/app-layer
objects (WebServer, ApplicationSolution, DatabaseSchema, WebApplication,
DBServer, Rack) that are not host-like and are not lookup targets here. There
is **no `PC` class in this instance** — re-verified live 2026-08-14 via
`core/get` on `Server`, `VirtualMachine`, `NetworkDevice`, `Hypervisor`.
Captured responses: `tests/fixtures/itop_demo_real.json`.

Practical consequence: none of this demo data's hostnames will ever match a
real Security Onion alert's `host.name` (which looks like `win-kvkmd51ggkq`,
not `Server1`). Until this iTop is populated with real asset records for real
hosts, `itop_asset_lookup` will return `found=False` for every production
alert. That is a data-population fact about *this* backend, same conclusion
architecture §17 already draws about iTop generally — not a code bug, and not
something to code around.

WHAT THIS iTOP DOES NOT HAVE — re-verified 2026-08-14, not assumed:

    network_zone       no such attribute on any class; the IP Management
                       extension is absent (`IPv4Subnet`/`IPv4Address` are not
                       valid classes)
    data_sensitivity   no such attribute on any class
    owner              no owner attribute; contacts_list is empty on every
                       object sampled (Server1, VM1, Router1, ESX1)
    ip addresses       `managementip` exists as an attribute on Server/
                       NetworkDevice but is blank on every object; PhysicalInterface
                       returns 0 rows. IP is NOT a usable lookup key.
    asset_number       exists as an attribute (it's a `PhysicalDevice` field,
                       same as before) but is BLANK on every object checked
                       (all 4 Servers, Router1) — same empty-field situation as
                       `ip_addresses`/`owner` above, just re-discovered on a
                       different instance. The asset_number-primary /
                       hostname-fallback lookup strategy below is kept as-is:
                       it is forward-compatible (starts working the moment
                       asset_number is populated) and costs nothing when it
                       isn't.

These are a DATA-POPULATION task, not a code one (architecture §17). When
custom fields or real asset records are added in iTop the extension here is
purely additive: one extra field read, same return model, no downstream
change. Subnet maps must NOT be introduced anywhere to synthesise
`network_zone`.

`asset_type` has no single source field across classes in this schema (unlike
the old `PC` class, which had a literal `type` attribute, e.g. `"desktop"` —
see the superseded `type: "desktop"` in the old fixture, kept only as a
historical note). Priority order, live-verified: `type` (still checked first,
for forward-compat with any future `PC`-like class) -> `networkdevicetype_name`
(populated on `NetworkDevice`, e.g. `"Router"` for Router1 — this is that
class's actual "what kind of device" field) -> `model_name` (populated on
`Server`/`NetworkDevice`, e.g. `"DL380"` — the closest fallback for classes
with neither). `VirtualMachine`/`Hypervisor` have none of the three, so
`asset_type` is `None` for those.

TWO THINGS THE REAL API DOES THAT ARE EASY TO GET WRONG (still true on this
instance, re-verified 2026-08-14):

1. `output_fields: "*"` returns only the attributes of the CLASS YOU QUERY, not
   of the object's actual subclass. Querying `FunctionalCI` for `Server::1`
   returns none of `os_family`/`location`/`model_name` even though the Server
   has them, and querying `PhysicalDevice` for asset_number would miss
   `osfamily_name` too. Hence the two-phase lookup below: locate, then
   re-fetch on `finalclass`.

2. `asset_number` is not a filterable attribute on `FunctionalCI` — the API
   rejects it. The exact wrapper text changed on this iTop version/build (now
   `"Query failed to execute: ... exception_class = OqlNormalizeException,
   exception_message = Unknown filter code - found 'asset_number' ..."`,
   previously just `"Unknown filter code - found 'asset_number' ..."` directly)
   — `"Unknown filter code"` is still a substring of the message either way,
   which is what the code/tests match on; re-verified live 2026-08-14, real
   response in `tests/fixtures/itop_demo_real.json["error_unknown_filter"]`.
   `asset_number` exists on `PhysicalDevice` and its subclasses only.
   `VirtualMachine` does not have it at all (VMs derive from VirtualDevice, not
   PhysicalDevice), so the UUID join cannot match a VM and the hostname
   fallback is what covers them.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time

import httpx

import config
from schemas import AssetContext, Gap

logger = logging.getLogger(__name__)

TOOL_NAME = "itop_asset_lookup"
SOURCE = "itop"

REST_VERSION = "1.3"

# Observed across all 32 live CIs on 2026-08-08: low (27), medium (2), high (3).
# iTop's OQL does not validate enum values in a WHERE clause (an invalid value
# returns 0 rows rather than an error), so this is an observed set, not a
# schema-derived one. An unseen value is passed through unchanged and logged,
# never silently coerced — a new tier appearing is something to find out about.
KNOWN_CRITICALITY_VALUES = {"low", "medium", "high"}

# Hostnames arrive from Security Onion telemetry and are attacker-influenceable,
# and they are interpolated into an OQL string. Anything outside this set is
# rejected rather than escaped — no legitimate hostname needs it, and rejecting
# is safer than trusting an escaping routine against a query language whose
# quoting rules we do not control.
_SAFE_OQL_VALUE = re.compile(r"^[A-Za-z0-9._:-]{1,255}$")


class ItopOqlValueError(ValueError):
    """A lookup key contained characters unsafe to interpolate into OQL."""


def _check_oql_value(value: str, label: str) -> str:
    if not _SAFE_OQL_VALUE.match(value or ""):
        raise ItopOqlValueError(
            f"{label} {value!r} contains characters not permitted in an OQL literal"
        )
    return value


def _normalise_criticality(raw: str | None) -> str | None:
    if raw is None:
        return None
    value = str(raw).strip().lower()
    if not value:
        return None
    if value not in KNOWN_CRITICALITY_VALUES:
        logger.warning(
            "%s: unrecognised business_criticity %r (known: %s) — passing through",
            TOOL_NAME,
            raw,
            sorted(KNOWN_CRITICALITY_VALUES),
        )
    return value


def _as_list(value) -> list[str]:
    """iTop returns link-set attributes as `[]` or a list of link objects, and
    occasionally as the string `'[]'`."""
    if not value or value == "[]":
        return []
    if isinstance(value, list):
        out = []
        for item in value:
            if isinstance(item, dict):
                name = item.get("friendlyname") or item.get("name")
                if name:
                    out.append(str(name))
            elif item:
                out.append(str(item))
        return out
    return []


def _blank_to_none(value):
    """iTop returns unset scalars as `''` and unset external keys as `'0'`,
    neither of which should reach the model as a value."""
    if value in (None, "", "0"):
        return None
    return value


async def _itop_call(payload: dict, timeout: float) -> dict:
    """POST to the iTop REST endpoint. Raises on transport or HTTP error."""
    data = {
        "auth_user": config.ITOP_USER,
        "auth_pwd": config.ITOP_PWD,
        "json_data": json.dumps(payload),
    }
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.post(
            f"{config.ITOP_URL}/webservices/rest.php",
            params={"version": REST_VERSION},
            data=data,
        )
        response.raise_for_status()
        return response.json()


async def _itop_get(cls: str, oql: str, timeout: float, fields: str = "*") -> dict:
    return await _itop_call(
        {"operation": "core/get", "class": cls, "key": oql, "output_fields": fields},
        timeout=timeout,
    )


def _first_object(payload: dict) -> tuple[str, dict] | None:
    """iTop returns `objects` keyed by `"<Class>::<id>"`. A non-zero `code` is
    an application-level error even though the HTTP status was 200 — iTop does
    not use HTTP status codes for API errors."""
    if payload.get("code") not in (0, "0"):
        raise RuntimeError(f"iTop error {payload.get('code')}: {payload.get('message')}")
    objects = payload.get("objects") or {}
    for key, obj in objects.items():
        return key, obj
    return None


def _build_asset_context(key: str, obj: dict, matched_by: str) -> AssetContext:
    fields = obj.get("fields") or {}
    itop_class = obj.get("class") or fields.get("finalclass")
    _, _, itop_id = key.partition("::")

    return AssetContext(
        found=True,
        hostname=_blank_to_none(fields.get("name")),
        criticality=_normalise_criticality(fields.get("business_criticity")),
        # No owner attribute exists in this iTop — see module docstring.
        owner=None,
        organization=_blank_to_none(
            fields.get("organization_name") or fields.get("org_id_friendlyname")
        ),
        services=_as_list(fields.get("services_list")),
        # Neither attribute exists in this iTop — see module docstring.
        network_zone=None,
        data_sensitivity=[],
        asset_type=_blank_to_none(
            fields.get("type") or fields.get("networkdevicetype_name") or fields.get("model_name")
        ),
        # No object in this iTop carries an IP — see module docstring.
        ip_addresses=[],
        asset_number=_blank_to_none(fields.get("asset_number")),
        itop_class=itop_class,
        itop_id=itop_id or None,
        matched_by=matched_by,
        status=_blank_to_none(fields.get("status")),
        os_family=_blank_to_none(fields.get("osfamily_name")),
        os_version=_blank_to_none(fields.get("osversion_name")),
        location=_blank_to_none(fields.get("location_name")),
        obsolete=fields.get("obsolescence_flag")
        if isinstance(fields.get("obsolescence_flag"), bool)
        else None,
    )


async def _locate(hostname: str | None, host_id: str | None, timeout: float):
    """Find the object, primary key first.

    Returns `(key, obj, matched_by, queried_class)` or None. The queried class
    is threaded out because the caller needs it to decide whether a re-fetch on
    the real subclass is required — see `_refetch_on_final_class`.

    `asset_number` is tried first because, when populated, it's a stable UUID
    that matched `event_data.host.id` exactly on a real alert against the old
    deployment's iTop, whereas hostname comparison in OQL `=` is case-sensitive
    and breaks on FQDN vs short name. On the *current* deployment's instance
    `asset_number` is blank on every object (module docstring) so this branch
    never matches today — it's kept because it's free and forward-compatible.
    It must be queried on `PhysicalDevice`; it is not filterable on
    `FunctionalCI`.

    The hostname fallback queries `FunctionalCI` deliberately — the broadest
    class — so that a VirtualMachine (which has no `asset_number`) or any other
    CI type still resolves.
    """
    if host_id:
        _check_oql_value(host_id, "host_id")
        found = _first_object(
            await _itop_get(
                "PhysicalDevice",
                f'SELECT PhysicalDevice WHERE asset_number = "{host_id}"',
                timeout,
            )
        )
        if found:
            return found[0], found[1], "asset_number", "PhysicalDevice"

    if hostname:
        _check_oql_value(hostname, "hostname")
        found = _first_object(
            await _itop_get(
                "FunctionalCI", f'SELECT FunctionalCI WHERE name = "{hostname}"', timeout
            )
        )
        if found:
            return found[0], found[1], "hostname", "FunctionalCI"

    return None


async def _refetch_on_final_class(
    key: str, obj: dict, queried_class: str, timeout: float
) -> dict:
    """Re-fetch on the object's real subclass so the full field set comes back.

    `output_fields: "*"` yields only the queried class's attributes. Locating via
    `FunctionalCI` misses `asset_number`/`status`; locating via `PhysicalDevice`
    misses `osfamily_name`. Both are wanted, so the object is re-read on its
    `finalclass` once it is known.

    A failure here is non-fatal: the partial object from the locate phase is
    still a valid, useful result.
    """
    # NOTE `obj["class"]` is the object's ACTUAL class, not the class that was
    # queried — comparing against it makes this a silent no-op, which is how the
    # first live run lost osfamily_name and asset_number. `queried_class` must
    # be threaded down from the locate phase.
    final_class = obj.get("fields", {}).get("finalclass") or obj.get("class")
    if not final_class or final_class == queried_class:
        return obj

    _, _, itop_id = key.partition("::")
    if not itop_id.isdigit():
        return obj

    try:
        found = _first_object(
            await _itop_get(
                final_class, f"SELECT {final_class} WHERE id = {int(itop_id)}", timeout
            )
        )
    except Exception as exc:  # noqa: BLE001 — partial data beats no data
        logger.debug("%s: refetch on %s failed, using partial: %s", TOOL_NAME, final_class, exc)
        return obj
    return found[1] if found else obj


async def itop_asset_lookup(
    hostname: str | None,
    host_id: str | None = None,
    timeout: float | None = None,
) -> tuple[AssetContext, Gap | None]:
    """Look up an asset by Elastic Agent host UUID, falling back to hostname.

    NEVER RAISES. Returns `(AssetContext, Gap | None)`:

    - found        -> `(populated AssetContext, Gap | None)`. A Gap is STILL
                      returned alongside a successful lookup when the asset has
                      no criticality, because architecture §10's impact scoring
                      silently degrades to a constant in that case and §17 calls
                      that the single biggest deployment risk. A found-but-blank
                      asset must not look like a fully successful lookup.
    - not in CMDB  -> `(AssetContext(found=False), Gap)` — a real result, not a
                      failure, and its reason says so.
    - backend fail -> `(AssetContext(found=False), Gap)` with the transport error
    """
    timeout = timeout if timeout is not None else config.STAGE_1_TOOL_TIMEOUT_ITOP
    started = time.monotonic()

    def elapsed_ms() -> int:
        return int((time.monotonic() - started) * 1000)

    def gap(reason: str) -> Gap:
        return Gap(source=SOURCE, tool=TOOL_NAME, reason=reason, duration_ms=elapsed_ms())

    if not hostname and not host_id:
        return AssetContext(found=False), gap(
            "Alert carried neither a hostname nor a host id — nothing to look up"
        )

    try:
        located = await asyncio.wait_for(
            _locate(hostname, host_id, timeout), timeout=timeout
        )
    except asyncio.TimeoutError:
        logger.warning("%s timed out after %.1fs for %s", TOOL_NAME, timeout, hostname)
        return AssetContext(found=False, hostname=hostname), gap(
            f"Timeout after {timeout}s querying iTop at {config.ITOP_URL}"
        )
    except ItopOqlValueError as exc:
        logger.warning("%s rejected an unsafe lookup value: %s", TOOL_NAME, exc)
        return AssetContext(found=False), gap(f"Unsafe lookup value: {exc}")
    except httpx.HTTPStatusError as exc:
        body = (exc.response.text or "")[:200].replace("\n", " ")
        return AssetContext(found=False, hostname=hostname), gap(
            f"HTTP {exc.response.status_code} from iTop: {body}"
        )
    except httpx.ConnectError as exc:
        return AssetContext(found=False, hostname=hostname), gap(
            f"Cannot connect to iTop at {config.ITOP_URL}: {exc}"
        )
    except Exception as exc:  # noqa: BLE001 — a tool must never raise into gather
        logger.warning("%s failed for %s: %s", TOOL_NAME, hostname, exc)
        return AssetContext(found=False, hostname=hostname), gap(
            f"{type(exc).__name__}: {exc}"
        )

    if located is None:
        return AssetContext(found=False, hostname=hostname), gap(
            f"No CMDB object matched asset_number={host_id!r} or name={hostname!r}"
        )

    key, obj, matched_by, queried_class = located
    try:
        obj = await asyncio.wait_for(
            _refetch_on_final_class(key, obj, queried_class, timeout), timeout=timeout
        )
    except asyncio.TimeoutError:
        logger.debug("%s: refetch timed out, using partial object", TOOL_NAME)

    try:
        context = _build_asset_context(key, obj, matched_by)
    except Exception as exc:  # noqa: BLE001
        logger.warning("%s could not map %s: %s", TOOL_NAME, key, exc)
        return AssetContext(found=False, hostname=hostname), gap(
            f"Object mapping failed for {key}: {type(exc).__name__}: {exc}"
        )

    if context.criticality is None:
        return context, gap(
            f"Asset {key} found but has no business_criticity — impact scoring "
            f"will fall back to its baseline for this alert"
        )

    return context, None
