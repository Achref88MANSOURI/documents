# SOC-3s — Implementation Guide

**Read this alongside `SOC-3s-ARCHITECTURE.md`.** That document says *what* to build and *why*. This document says *in what order* and *how to verify each piece as you go*, including two project-specific corrections that are easy to get wrong if you're inferring from general SOC/agent knowledge instead of this environment's actual behavior.

---

## 0. Two corrections before you write anything

### 0.1 — Only Sigma alerts can be produced right now. This is expected, not a bug.

This Security Onion deployment does not yet have network sensors deployed. That means:

- **Sigma alerts fire** — endpoint telemetry (Elastic Agent / Sysmon) is live, ElastAlert2 evaluates Sigma rules against it, alerts land in `.ds-logs-detections.alerts-so-*`.
- **Suricata alerts do not fire** — no sensor is watching network traffic. The Suricata alert index does not exist yet.
- **YARA/Strelka alerts do not fire** — no file-extraction path is active yet. Same situation.

**What this means for the build:**

- Build all three engine-specific code paths as designed in the architecture doc (`detection_rule_lookup`'s per-language parsing, `alert_builder`'s per-engine field extraction, the `investigation_profile` mapping). Do not skip Suricata/YARA code just because you can't test it live.
- **But test only against Sigma live data.** Every "call the real backend and confirm" step in this guide, for anything alert-shape-dependent, uses a real Sigma alert. Suricata/YARA code paths get unit tests against synthetic fixtures built from `so-alert-reference/` (see below) — they cannot be integration-tested against a live alert until sensors are deployed.
- Mark this explicitly in test file docstrings: `# NOTE: Suricata path — unit-tested against synthetic fixture only, no live SO alert exists yet to validate against.`
- Do not let this partial coverage block calling the build "done." Sigma-only is the correct, expected state of this deployment today.

### 0.2 — Security Onion does not put IOCs in the raw alert. Do not try to make it.

This is a common wrong assumption to carry in from general threat-intel-pipeline knowledge, so it's worth stating precisely:

**The raw Security Onion alert document — for Sigma, which is 100% of what you can currently test — has no `ioc`, `observables`, or `indicators` field.** It has `rule.*`, `event.*`, and `event_data.*` (the matched log document). There is no built-in Security Onion mechanism that extracts "this command line contains a URL, this field is a hash" into a clean list on the alert itself.

(Security Onion *does* have a `so-ioc-normalize` ingest pipeline, but it only ever populates for Suricata/network alerts in this deployment, and even then only when the traffic path is active — which it isn't. For Sigma, it's always empty. Don't build logic that depends on it being populated.)

**Where IOCs actually come from in this system: a separate n8n step, not agent-service.**

Before `/triage` is ever called, an n8n workflow node — call it the *n8n alert builder* — does the following, independent of anything in this repository:

1. Receives the raw Security Onion webhook payload
2. Extracts IOC-shaped values out of it (regex over command lines for URLs/domains, hash fields, IPs) — this extraction logic lives entirely in n8n, not in this codebase
3. Creates the TheHive alert with those extracted values populated as `observables: [{dataType, data, ioc, tags}, ...]`
4. *Then* n8n calls `POST /triage` with `{thehive_alert_id, raw_alert, asset_context}`

**Consequence for this codebase:** `alert_builder.py`'s job is to parse `raw_alert` for normalized entity fields (host, user, process, rule, network) — never to extract IOCs from it. IOCs for this `CanonicalAlert` come from a *second* source, fetched from TheHive: `hive_alert.observables`, retrieved via `get_full_alert_with_analysis(thehive_alert_id)` — the same function this fetches Cortex reports through (`extraData: ["reports"]`, because TheHive 5 excludes Cortex reports from observable responses by default).

If you find yourself writing regex to pull URLs or hashes out of `raw_alert.event_data.process.command_line` inside this repo — stop. That work is already done, upstream, in n8n. Re-doing it here duplicates logic across two systems and will drift out of sync. This repo trusts `hive_alert.observables` as the IOC source of truth.

---

## 1. Reuse, don't rebuild: what to bring into the new repo verbatim

Two artifacts already exist from prior work on this project and should be carried into the new repository rather than rewritten:

### 1.1 — `alert_builder.py` (the working module, not a rewrite)

This module already:

- Parses the real raw Sigma webhook payload shape (top-level `rule`, `event`, `event_data` — not a flattened or TheHive-shaped fixture)
- Handles the four confirmed `event_data.event.dataset` shapes actually seen in this deployment's live traffic: `endpoint.events.process` (93% of volume), `windows.sysmon_operational`, `endpoint.events.file`, plus stub coverage for the smaller-volume shapes
- Correctly implements `_merge_observables`, sourcing IOCs from `hive_alert.observables` (primary) with `raw_alert.ioc.indicators` as an always-empty-for-Sigma supplementary source (kept for when Suricata/YARA eventually populate it)
- Has 160 passing tests
- Has already had 6 real field-path bugs found and fixed by cross-referencing against `so-alert-reference/` and a live 4-week Elasticsearch field-mapping dump — not by guessing

**Action:** Copy this file into the new repo at `alert_builder.py` unmodified as the starting point. Do not regenerate it from the architecture doc's description alone — the architecture doc describes its *role* in the pipeline, this file is the validated *implementation* of that role.

**What will need to change in it for the new pipeline** (small, targeted edits — not a rewrite):

- Its output type (`CanonicalAlert`) must match exactly the `schemas/alert.py` definition in the new repo. If any field names differ, reconcile by editing `alert_builder.py` to match the new schema — the schema is the new contract, the old field names are not sacred.
- Confirm `investigation_profile` values it emits (`network_threat`, `endpoint_behavior`, `malicious_file`, `generic`) match exactly what `nodes/gather.py` and `nodes/rag.py` will switch on for deterministic tool/retrieval selection (§6–7 of the architecture doc).

### 1.2 — `so-alert-reference/` (reference material, not a runtime dependency)

This is the partial sparse-checkout of the real `Security-Onion-Solutions/securityonion` repo (ingest pipelines + ECS/SO component templates), plus the extracted `securityonion-es.py` Sigma alerter source and a real generated Sigma ElastAlert rule YAML. 318 files, already transferred and verified.

**Action:** Copy the entire `so-alert-reference/` folder into the new repo root, unchanged. It is **build-time only** — nothing in `nodes/`, `tools/`, or `main.py` ever reads from this folder at runtime. Its only purpose is to be there for Claude Code (or a human) to consult when:

- Extending `alert_builder.py` to handle a new `event_data.event.dataset` shape that shows up in production later
- Eventually building out real Suricata/YARA field extraction once those sensors are live and produce real alerts to verify against
- Resolving any doubt about "what field does Security Onion actually call this" instead of guessing

Add a one-line note at the top of `so-alert-reference/CONTEXT.md` (create this file if it doesn't already exist) stating: `Build-time reference only. Not imported by any runtime module. See ARCHITECTURE.md §1 and IMPLEMENTATION-GUIDE.md §1.2.`

---

## 2. The verification discipline for every new tool

This is the core practice for this build: **a tool function is not "done" when it type-checks or passes a mocked unit test. It is done when it has been called against the real, live backend at least once during development, and the actual response shape has been inspected and matches what the Pydantic return model expects.**

Mocked unit tests are still required for CI (backends won't always be reachable in automated test runs) — but they get written *after* the real call has been made and the real response shape is known, not before, and not instead of.

### The loop for every tool in `tools/*.py`

For each tool function (`get_fp_signal`, `detection_rule_lookup`, `search_open_cases_by_entities`, `search_closed_cases_by_rule`, `itop_asset_lookup`, `elasticsearch_related_alerts`, `elasticsearch_process_history`, `qdrant_retrieve` ×3 collections):

1. **Write the function signature and return type** — the Pydantic model it returns, matching `schemas/evidence.py`. Do not write the body logic yet beyond a `raise NotImplementedError`.

2. **Write the real backend call, minimal, no error handling yet.** Just enough to hit the actual endpoint (ES, TheHive, iTop, Qdrant, SQLite) and get a raw response.

3. **Run it against the real backend, right now, from a scratch script or REPL** — not through pytest, not mocked:
   ```bash
   python -c "
   import asyncio
   from tools.itop import itop_asset_lookup
   result = asyncio.run(itop_asset_lookup('win-kvkmd51ggkq'))
   print(result)
   "
   ```
4. **Look at the actual output.** Compare it field-by-field against the Pydantic model you wrote in step 1. If iTop returns `location_name` and your model expects `location`, fix the mapping now, in this tool function — not later when Stage 1 silently gets `None` for a field you thought was populated.

5. **Only after the real call has produced a real, inspected result** — add the try/except, the timeout wrapper, and the failure-path `Gap(source=..., reason=...)` construction.

6. **Write the pytest test** using a fixture that is the *actual captured response* from step 3-4 (saved as a JSON fixture file), not an imagined one. Add a second test that mocks a timeout/connection error and confirms it produces a `Gap`, not an exception.

7. **Only then** wire the tool into `nodes/gather.py`'s `asyncio.gather(...)` call.

**Do not build all seven tools and then test them together for the first time inside `nodes/gather.py`.** If you do, and three of them have subtly wrong field mappings, you'll be debugging three bugs at once inside an async gather, which is much harder than catching each one standalone in step 4 above.

### Where to get real inputs for step 3, per tool

| Tool | Real input to test with |
|---|---|
| `get_fp_signal` | Any `(rule_uuid, host)` pair — even one with zero history is a valid real result to inspect |
| `detection_rule_lookup` | A `rule.uuid` from a real captured Sigma alert (e.g. `5e3cc4d8-3e68-43db-8656-eaaeefdec9cc`, the Invoke-WebRequest rule already captured earlier in this project) |
| `search_open_cases_by_entities` | Real observable values / hostname from a real alert, against the live TheHive instance |
| `search_closed_cases_by_rule` | Same `rule.uuid` as above — expect empty results this early in deployment, and that IS the correct real result to verify |
| `itop_asset_lookup` | The real hostname `win-kvkmd51ggkq` from the captured alert, against the live iTop instance — **expect this to matter most**, see §3 below |
| `elasticsearch_related_alerts` | The real host/user from a captured alert, against the live `.ds-logs-detections.alerts-so-*` index |
| `elasticsearch_process_history` | Same, against `.ds-logs-endpoint.events.process-*` (confirmed live, 7176 documents) |
| `qdrant_retrieve` (mitre) | A real technique-relevant query string once the MITRE collection is ingested (§4 below) |

---

## 3. The iTop dependency — flag this immediately, don't discover it late

The architecture doc (§13, §17) already flags this as the single biggest deployment risk: `impact` scoring depends entirely on `itop_asset_lookup` returning real criticality data. If iTop only has default/empty entries for the hosts Security Onion monitors, this whole scoring dimension degrades to a constant.

**Do this in step 3-4 of the tool-verification loop for `itop_asset_lookup`, before writing anything else that depends on it:**

```bash
python -c "
import asyncio
from tools.itop import itop_asset_lookup
result = asyncio.run(itop_asset_lookup('win-kvkmd51ggkq'))
print(result)
"
```

If this returns `{"found": false, ...}` or `{"found": true, "criticality": null, ...}` — **stop and report this back before continuing the build.** It means either:
- The hostname format iTop expects doesn't match what Security Onion alerts carry (worth checking against a couple of real hostnames), or
- iTop genuinely has no criticality data for this asset yet, which is a data-population task, not a code task

Either way, this is worth knowing in week 1, not discovering in week 3 when every alert's impact score is coming back identical.

---

## 4. Qdrant collections — build and verify one at a time, in this order

1. **`mitre_techniques` first.** Run `scripts/ingest_mitre.py` against the real MITRE ATT&CK STIX bundle. Then immediately verify with a real query:
   ```bash
   python -c "
   import asyncio
   from tools.qdrant import qdrant_retrieve
   results = asyncio.run(qdrant_retrieve('mitre_techniques', 'PowerShell download credential dumping tool', top_k=5))
   for r in results: print(r.technique_id, r.technique_name, r.score)
   "
   ```
   Confirm the top result is something plausible (e.g. T1105 or T1059.001 for that query) before moving on. If the top result is nonsense, the embedding or the ingested payload text is wrong — fix here, not after wiring into Stage 2.

2. **`soc_playbooks` second.** This needs at least a handful of hand-authored playbooks before it's testable at all. Author 3–5 initial playbooks (not the full 10+ target from the architecture doc's deployment checklist — just enough to verify the retrieval mechanism works) covering patterns you already know fire in this deployment: PowerShell download cradle, credential dumping tool execution, WScript/CScript dropper (these all match real Sigma rule titles already seen in this project's captured alerts). Ingest, then verify retrieval the same way as MITRE above.

3. **`cve_context` last, and only if time allows.** The architecture doc already marks this as marginal value (§7). Do not let this block the rest of the build. It's fine to ship Stage 2 with only MITRE + playbooks active and CVE retrieval stubbed to always return `[]` until there's time for it.

---

## 5. Stage 3 / Stage 4 — verify the LLM calls the same disciplined way

Once `nodes/context.py` and `nodes/analyze.py` are written (per architecture doc §8–9), do not consider them done until:

1. **A real `EnrichedEvidence` object** (built from steps above, against the real captured alert) is passed through the actual prompt builder in `prompts/context_agent.py`, and the actual rendered prompt string is printed and read — confirming no `{field}` placeholders are left unfilled, no `None` values are rendering as the literal string `"None"` in a way that would confuse the model.

2. **The real LLM endpoint is called** (`qwen3.5:4b` for Stage 3, `foundation-sec-reasoning` for Stage 4, both already deployed on the Ollama host) with that real prompt, and the raw response is inspected before writing the Pydantic parsing logic — not after.

3. **The deterministic fallback path is deliberately triggered** at least once during development (e.g. by pointing `LLM_BASE_URL` at an unreachable port temporarily) to confirm it produces a valid `ContextualAssessment` / `TriageVerdict` with the correct degraded defaults, not an unhandled exception.

---

## 6. Definition of done for this implementation pass

Do not report the build as complete until:

- [ ] Every tool in `tools/*.py` has been called at least once against its real live backend during development (not only mocked), with the response shape confirmed to match its Pydantic model
- [ ] `alert_builder.py` (carried over) and `so-alert-reference/` (carried over) are both present in the new repo, with the build-time-only note added to the reference folder
- [ ] The iTop check from §3 has been run and reported, whatever the result
- [ ] At least the `mitre_techniques` and `soc_playbooks` Qdrant collections are populated and retrieval-verified with real queries
- [ ] One full pipeline run (Stage 0 → 6) has been executed against a real captured Sigma alert end-to-end, hitting real backends (not the full mocked test suite — an actual `curl POST /triage`), and the resulting `TriageResult` has been read and sanity-checked by a person
- [ ] Suricata/YARA code paths exist and have synthetic-fixture unit tests, explicitly marked as not live-verified, per §0.1

This list is the actual finish line — not "all files exist" and not "pytest is green." Green tests against mocks and a working pipeline against real backends are different claims; this project has been burned by that gap before.