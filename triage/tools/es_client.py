"""Shared async Elasticsearch transport.

NOT a tool — a transport helper. It holds no query logic and returns raw JSON.
`tools/detection_rules.py` and `tools/elasticsearch.py` both need identical
auth, TLS and timeout handling against the same cluster; duplicating it in two
places is how the two drift apart.

Uses `httpx` directly rather than the `elasticsearch` client library, which is
not installed in this environment. The queries this service issues are simple
`_search` posts — the client library would add a dependency for no benefit.

TLS verification is off by default: the Security Onion manager presents a
self-signed certificate. `ES_VERIFY_TLS=true` turns it back on.
"""

from __future__ import annotations

from typing import Any

import httpx

import config


def es_headers() -> dict[str, str]:
    """`ES_API_KEY` is optional — an Elasticsearch with no auth is a valid
    configuration, so an empty key omits the header rather than sending an
    empty one (which ES rejects with 401 rather than treating as anonymous)."""
    headers = {"Content-Type": "application/json"}
    if config.ES_API_KEY:
        headers["Authorization"] = f"ApiKey {config.ES_API_KEY}"
    return headers


async def es_search(index: str, body: dict[str, Any], timeout: float) -> dict[str, Any]:
    """POST `<index>/_search`. Raises on transport error or non-2xx — callers
    are responsible for converting that into a `Gap`.

    `allow_no_indices` / `ignore_unavailable` are set so that querying an index
    that does not exist yet returns an empty result rather than a 404. This
    matters directly: the Suricata and Strelka alert indices do not exist in
    this deployment (implementation guide §0.1), and a missing index should read
    as "no results", not as a backend failure.
    """
    params = {"allow_no_indices": "true", "ignore_unavailable": "true"}
    async with httpx.AsyncClient(verify=config.ES_VERIFY_TLS, timeout=timeout) as client:
        response = await client.post(
            f"{config.ES_URL}/{index}/_search",
            headers=es_headers(),
            params=params,
            json=body,
        )
        response.raise_for_status()
        return response.json()


def describe_http_error(exc: Exception) -> str:
    """A Gap reason a human can act on. `str(httpx.HTTPStatusError)` alone is a
    wall of URL; the status code and response snippet are what actually
    identify the problem."""
    if isinstance(exc, httpx.HTTPStatusError):
        body = (exc.response.text or "")[:200].replace("\n", " ")
        return f"HTTP {exc.response.status_code} from Elasticsearch: {body}"
    if isinstance(exc, httpx.ConnectError):
        return f"Cannot connect to Elasticsearch at {config.ES_URL}: {exc}"
    if isinstance(exc, httpx.ReadTimeout):
        return f"Elasticsearch read timeout: {exc}"
    return f"{type(exc).__name__}: {exc}"
