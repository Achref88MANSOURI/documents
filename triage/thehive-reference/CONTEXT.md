Build-time reference only. Not imported by any runtime module.

# `getAlertWithObservables` — HISTORICAL, RETIRED 2026-08-13

**This dependency no longer exists and is no longer needed.** TheHive moved
again and was upgraded to 5.7.5-1 (172.20.24.228). The custom Function
described below is gone — `POST /api/v1/function/getAlertWithObservables`
now returns `404 Function getAlertWithObservables not found`. But the
external-API limitation that made the Function necessary is *also* gone: the
stock `getAlert -> observables -> page` projection now returns
`reports[analyzer].taxonomies` directly, no `extraData` needed, confirmed
live 2026-08-13 against real alerts. `tools/thehive.py::get_full_alert_with_
analysis` was rewritten to two concurrent stock queries and no longer depends
on this Function at all — it was not re-registered.

Kept below as history: it explains a real, previously-live dependency and the
investigation that led to it, in case a future TheHive version regresses back
to the old external-API behaviour and this pattern needs reviving.

---

## (Historical) `getAlertWithObservables` — a HARD RUNTIME DEPENDENCY, as of 2026-08-09

`tools/thehive.py::get_full_alert_with_analysis` USED TO call a **custom
TheHive Function**, not a stock endpoint:

    POST {THEHIVE_URL}/api/v1/function/getAlertWithObservables
    {"alertId": "~4168"}

`getAlertWithObservables.json` in this folder is its exact registered
definition, captured 2026-08-09 from the live instance. **If the Function is
lost — a TheHive upgrade, a renamed org, a wiped config — re-register it from
that file**, otherwise the pipeline silently loses all threat-intel signal.

## Why a custom Function is needed at all

TheHive's *external* API does not expose Cortex analyzer reports on observables.
Verified 2026-08-09 on TheHive 5.7.3, three independent ways, all returning
`['artifacts','full','success']` with `summary: null` or nothing at all:

- `extraData: ["reports"]` on observables — key silently dropped (only `shares`
  and `seen` return). Six key spellings tried.
- `extraData: ["report"]` on jobs — returns a report, but no `summary`.
- `GET /api/connector/cortex/job/{id}` — same, no `summary`.

The Function works because `context.query.execute()` runs against TheHive's
**internal** query engine, whose observable serialiser *does* include
`reports[analyzerName].taxonomies`. Two different serialisers, one API.

## Re-registering it

    curl -X POST '{THEHIVE_URL}/api/v1/function' \
      -H 'Authorization: Bearer <key>' -H 'Content-Type: application/json' \
      -d @getAlertWithObservables.json

## Shape it returns

    {"result": {"alert": {...}, "observables": [ {..., "reports": {
        "<AnalyzerName>": {"taxonomies": [{level, namespace, predicate, value}]}
     }} ]}, "durationMillis": 0, "stdout": "...", "stderr": ""}

Note `reports[analyzer].taxonomies` is NOT wrapped in `summary` — Cortex's own
API wraps it as `report.summary.taxonomies`. `alert_builder._build_cortex_results`
accepts both shapes for that reason.

## Failure behaviour

If the Function is absent the tool returns a `Gap`, never an exception. The
pipeline continues with no threat intel rather than failing the alert.
