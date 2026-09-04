# SOC-3s — Agent Operating Instructions

Read `SOC-3s-ARCHITECTURE-v4.md` in full before writing anything, and
`SOC-3s-IMPLEMENTATION-GUIDE.md` before writing the first tool function.

## Hard constraints

- Exactly 2 LLM calls per alert, in `nodes/context.py` and `nodes/analyze.py`. No more, anywhere.
- Neither LLM call has tool access. Both are single-shot completions.
- No ReAct loops, no tool-calling agents, no recursion-limit math. If you're about to write
  one, stop — re-read Architecture doc §2 and §14 first.
- Every stage input/output is a Pydantic model from `schemas/`. Never pass a raw dict between
  `nodes/*.py` files.
- Every backend call in `nodes/gather.py` runs inside `asyncio.gather(..., return_exceptions=True)`
  with an explicit per-tool timeout. A failed or slow backend produces a logged `Gap`, never
  an unhandled exception that reaches the caller.
- Stage 4's LLM never outputs a numeric score. It outputs likelihood/impact labels and
  `ContextualModifier` entries (dimension, factor_name, direction, strength, reasoning).
  `scoring.py` is the only place a number is computed.
- Build one node at a time, in the order given in Architecture §18. Write tests for each
  node before moving to the next. Stop for review after each node.

## What "done" means for each node

A node is done when: it has a typed Pydantic input and output, it has unit tests covering
the happy path and at least one failure/timeout path, and it never raises an unhandled
exception to its caller (`gather.py`) or never fails the whole pipeline (`context.py` /
`analyze.py`, which fall back to deterministic defaults on any LLM failure).

## What "done" means for each tool in `tools/*.py`

Per Implementation Guide §2, a tool is NOT done when it type-checks or passes a mocked
test. It is done when it has been called against the real, live backend at least once
during development and the actual response shape has been inspected against its Pydantic
model. Mocked tests are written *after* that, from the captured real response — never
instead of it.

---

## Deployment-specific decisions

These are decisions made for *this* environment that diverge from, or resolve ambiguity in,
the architecture document. They are deliberate. Do not "correct" them back toward the doc
without asking.

### Both LLM stages run `foundation-sec-reasoning`

Architecture §19 assigns `qwen3.5:4b` to Stage 3 and `foundation-sec-reasoning` to Stage 4.
**This deployment runs `foundation-sec-reasoning:latest` for both stages.** `qwen3.5:4b` is
deliberately not pulled — the Ollama host at `172.20.24.225` carries only
`foundation-sec-reasoning:latest` and `llama3.2:3b`.

**The trade-off this accepts:** reasoning consistency over latency. Stage 3 moves from the
doc's ~30–60s budget to roughly **60–90s**, the same envelope as Stage 4 (§9). That pushes
p95 end-to-end from the doc's 180s target toward **~200s**. This is still inside the 300s
n8n HTTP timeout budget, but with materially less headroom than the original two-model
design assumed.

**If latency becomes a real problem in operation, flag it back to the maintainer rather than
silently swapping models.** Model choice is a deployment decision, not an implementation
detail to tune away.

**Update 2026-08-16, flagging per the instruction above rather than silently working around
it:** it has. A real, live, end-to-end Stage 3 call (`nodes/context.py`, real `EnrichedEvidence`
built from the xordump alert through the real Stage 1→2 chain, real `foundation-sec-reasoning`
call) took **271.1 seconds**, well past this section's own "~60-90s" estimate and past the
architecture-default 120s `STAGE_3_LLM_TIMEOUT`. **This deployment's `.env` now sets
`STAGE_3_LLM_TIMEOUT=600`** so CPU inference has the time it actually needs during
development/testing. This is a config value only — `nodes/context.py`'s call logic does not
branch on CPU vs GPU anywhere; tighten the timeout once running against a GPU-backed endpoint,
don't touch the code.

### Ollama's `response_format: json_schema` mode hangs on Pydantic's default `$defs`/`$ref` schema output — must send a fully inlined schema

**Verified live 2026-08-16**, building `nodes/context.py` (Stage 3). Ollama's OpenAI-compatible
endpoint supports grammar-constrained JSON output via
`response_format: {"type": "json_schema", "json_schema": {...}}`, and it materially fixes the
self-continuation problem plain `json_object` mode has (below) — but only if the schema handed
to it has no `$defs`/`$ref`. `Pydantic.model_json_schema()` uses `$defs`/`$ref` by default for
any model with nested sub-models, which `ContextualAssessment` has (`refined_mitre_mapping`,
`contextual_modifiers`, `correlation_decision`). Sent as-is: **the call did not return after
280+ seconds**, killed by hand. The identical schema hand-inlined (all `$ref`s manually
expanded, zero `$defs`): completed in 68.9s on a toy prompt, clean schema-conformant output.

`prompts/context_agent.py::CONTEXTUAL_ASSESSMENT_SCHEMA` is therefore hand-written, not derived
from `ContextualAssessment.model_json_schema()`. `tests/test_context.py::TestSchemaStaysInSync`
guards against the two drifting apart on a future field change. This will matter again for
Stage 4's `TriageVerdict` schema (`prompts/analyst_agent.py`, not yet built) — same fix applies.

### Plain `response_format: json_object` mode is not safe — the model self-continues past the first JSON object

**Verified live 2026-08-16**, same investigation. Under plain `{"type": "json_object"}` mode
(no schema), `foundation-sec-reasoning:latest` emitted one valid JSON object as instructed, then
kept generating — several hallucinated "Would you like another? yes" Q&A turns with more
embedded JSON and prose appended after it. `json.loads()` on the full response string fails (or
silently returns the wrong thing if it happens to still parse). `nodes/context.py::
_extract_first_json_object` uses `json.JSONDecoder().raw_decode()` to take only the first JSON
value in the string, and stays defensive even under `json_schema` mode (which didn't reproduce
this in testing) since nothing guarantees a different prompt shape can't trigger it there too.

### Fixed — `merge_into_case_id` conflated a RAG match with an open case

**Observed 2026-08-16, fixed the same day.** On the first live real-alert run, the LLM populated
`correlation_decision.merge_into_case_id` with an ID (`"~8613944"`) that only existed in Stage
2's `incident_matches` (a Qdrant RAG-retrieved *semantically similar past incident*), not in
`evidence.open_cases` (TheHive's actual currently-open cases, empty in that run). The model was
treating "a similar historical incident" as if it were "a case to merge into," and the schema
didn't syntactically prevent it — `merge_into_case_id` was just a free `["string", "null"]`.

**Fix, in priority order (both live-verified, not just proposed):**

1. **Schema-level enum constraint** (primary, structural).
   `prompts/context_agent.py::build_contextual_assessment_schema(evidence)` now builds the
   output schema per-call: `correlation_decision.merge_into_case_id`'s `enum` is constrained to
   this specific alert's real `open_cases` IDs plus `null`, and `action`'s `enum` drops `"merge"`
   entirely when there are no open cases. Live-verified: re-running the exact real alert/prompt
   that produced the bug, with the enum forced to `[null]` (its real `open_cases` was empty),
   the model complied cleanly — `action: "new"`, `merge_into_case_id: null` — no error, no
   degraded analysis quality (still correctly identified T1059.001/T1071.001). This makes the
   wrong answer structurally unrepresentable rather than merely discouraged — the same mechanism
   already proven reliable for `confidence`/`strength`/etc.'s bounded enums.
2. **System prompt clarification** (secondary). `SYSTEM_PROMPT` now names `open_cases` vs
   `incident_matches` explicitly and states which one is a valid merge target — helps the
   free-text `reasoning`/`additional_investigation_gaps` fields, which no schema constraint
   reaches.
3. **Post-parse cross-check** (tertiary, defense-in-depth). `nodes/context.py::
   _validate_merge_target` nulls out and logs any `merge_into_case_id` that somehow isn't in
   `evidence.open_cases` even after the schema constraint — belt-and-suspenders for the case
   Ollama's schema enforcement doesn't hold (this investigation already saw model/host variance
   once: the `json_object` self-continuation, below).

**Re-verified live end-to-end through the actual fixed `nodes.context.context_analysis` code
path** (not just the standalone schema probe) against the exact same real evidence that
originally produced the bug: `merge_into_case_id: null`, `action: "new"`, 323.2s. Captured as
`tests/fixtures/context_live_run_fixed_real.json`. 11 new/updated tests in
`tests/test_context.py` (`TestDynamicMergeSchema`, `TestMergeTargetValidation`,
`TestMergeFixVerifiedLive`), mutation-checked.

### `ioc.*` is NOT a Security Onion field — never build on it

`raw_alert.ioc.{source_engine, schema_version, dataset, rule, indicators}` does
not exist in production Security Onion alerts. It came from a custom
development-time ingest pipeline. Evidence:

- `so-alert-reference/ingest/so-ioc-normalize` is that pipeline. Its own
  description says it runs as `final_pipeline` **after** "Security Onion's own
  suricata.alert -> common.nids -> common chain" — i.e. it declares itself an
  addition, not part of SO.
- It sets `ioc.source_engine = ctx.event.module`. The field is *derived from*
  `event.module`, so it can never independently corroborate it.
- `so-alert-reference/securityonion-es.py` — the real SO Sigma alerter — writes
  exactly `event.severity`, `event.module`, `event.dataset`. Nothing else.

**That pipeline is LIVE in this deployment, so real alerts do contain `ioc.*`.**
Verified 2026-08-08 by date histogram over the whole alerts index: `ioc.*` is
present on 100% of alerts from **2026-07-16 onward** (5571 of 7719) and on 0%
before. It is not a hand-edited artifact of one sample file — a fresh unmodified
pull from `.ds-logs-detections.alerts-so-*` still contains it, and
`tests/fixtures/sigma-alert-real.json` deliberately preserves it.

The rule is therefore **"present but never read"**, not "absent". Do not treat
finding `ioc.*` in real data as evidence it is safe to use.

(An earlier note here said "only 1 of 24 backing indices" carries an `ioc`
mapping. That was a misreading: `ingest-templates.txt` ends on 2026-07-16, the
exact day the pipeline went live, so the dump caught only its first day. The
count measured recency, not rarity.)

**Engine detection uses `event.module` first, then the `event.dataset` prefix.**
Verified live 2026-08-08: the entire alerts index is `event.module="sigma"` /
`event.dataset="sigma.alert"`, 7719 docs, 100% — matching guide §0.1.

`tests/test_alert_builder.py::test_ioc_field_is_ignored_entirely` is the
regression guard. Do not weaken it.

**Note this contradicts implementation guide §0.2**, which states Security Onion
"does have a `so-ioc-normalize` ingest pipeline". It does not — that pipeline is
custom. §0.2's *conclusion* is still correct and still binding: IOCs come from
`hive_alert.observables`, never from `raw_alert`. Only its attribution is wrong.

### Redis is not deployed

`REDIS_URL` is unset. Stage 0 dedup no-ops gracefully — architecture §5 requires that Redis
absence never blocks the pipeline. Cost: duplicate alerts within the dedup window are
processed more than once. This is the documented, accepted failure semantics.

### Cortex is not configured (this service never calls it directly)

This service never calls Cortex (§6, §13). Analyzer reports arrive pre-computed on the
TheHive alert, read via `get_full_alert_with_analysis`. **Updated 2026-08-13**: that
function no longer calls `extraData: ["reports"]` (that route never worked — see the
"TheHive moved again" entry below) or a custom Function. It now runs two concurrent stock
`/api/v1/query` calls (`getAlert`, and `getAlert -> observables -> page`), which return
`reports[analyzer].taxonomies` directly. `CORTEX_URL` / `CORTEX_API_KEY` remain in `.env`,
unused at runtime, as the documented (and currently 401ing — see SESSION-FINDINGS.md)
fallback if that ever breaks again.

### `FP_TRACKING_DB_PATH`, not `FP_DB_PATH`

Architecture §19 names the variable `FP_DB_PATH`. This deployment standardised on
`FP_TRACKING_DB_PATH`, which is what `config.py` reads.

### `ES_URL` must carry `:9200`

The bare host `https://172.20.24.58` returns a 302 to the SOC web UI on 443. Only
`https://172.20.24.58:9200` reaches Elasticsearch.

### TheHive moved and was upgraded again — the custom Function is retired

**2026-08-13.** TheHive is now at `http://172.20.24.228:9000`, version 5.7.5-1. The base
path is `/api/v1` directly — **not** `/thehive`; that old prefix now returns HTTP 200 with
the SPA's HTML, a trap for a naive health check (it looks reachable and isn't the API).

The custom `getAlertWithObservables` Function this deployment's whole threat-intel path
depended on (see `thehive-reference/CONTEXT.md`) is **gone** — `404 Function
getAlertWithObservables not found`. It was not re-registered, because the external-API
limitation that made it necessary is *also* gone: the stock `getAlert -> observables ->
page` projection now returns `reports[analyzer].taxonomies` directly, no `extraData`
needed, confirmed live against real alerts. `tools/thehive.py::get_full_alert_with_
analysis` was rewritten to two concurrent stock queries.

**Do not re-register the old Function** on the assumption it's still required — it isn't,
on this TheHive version. If a future upgrade regresses the external API back to hiding
`reports`, `thehive-reference/CONTEXT.md`'s historical section documents the pattern that
worked before.

### OpenCTI — a deployment-added Stage-1 tool, not in architecture v4

**2026-08-13.** `tools/opencti.py` (`opencti_observable_enrichment`) is a new Stage-1 tool,
beyond architecture v4 §6's original 7. It queries OpenCTI's GraphQL API directly for an
observable's graph context (known indicator status, related malware/threat-actor/campaign
via `stixCoreRelationships`) — live-verified reachable at `http://172.20.24.222:8080`,
GraphQL 7.260318.0.

**This is distinct from, and additional to, OpenCTI's own Cortex analyzer**
(`OpenCTI_v6_SearchExactObservable_2_0`), whose taxonomy rows already arrive through
`get_full_alert_with_analysis` alongside VirusTotal's — that path answers "did the SOC's
Cortex pipeline flag this," structured into `CortexResult` like any other analyzer.
`tools/opencti.py` answers a different question — "what does OpenCTI's own threat graph
say this observable relates to" — and returns `OpenCTIEnrichment`, never a score (graph
context only; `scoring.py` remains the only place a number is computed).

**A credential bug was found and fixed the same day**: the `OPENCTI_TOKEN` stored in
`.mcp.json` (`lgrn_octi_tkn_...`) was missing a leading `f` and 401s. The corrected value
(`flgrn_octi_tkn_...`) is now in both `.mcp.json` and `.env`'s `OPENCTI_TOKEN`.

### Suricata alert support — added 2026-08-18, and a real gap sitting upstream of all of it

**The codebase-side work.** `alert_builder.py` and `tools/detection_rules.py` handle a
Suricata-shaped `raw_alert` correctly now:

- `build_canonical_alert`'s `event_dataset` previously only read the nested
  `event_data.event.dataset` path (Sigma's embedded-event shape). Suricata/YARA have no
  `event_data` and carry the equivalent one level up, at `raw_alert.event.dataset`
  (`"suricata.alert"`) — the same top-level object `_source_engine()` already read for engine
  detection. Now falls back there when the nested path is absent.
- `tools/detection_rules.py::_parse_suricata_content` (new) parses Suricata's inline
  `metadata:key val, key2 val2, ...;` rule clause — a completely different encoding from
  Sigma's YAML `tags:` list, previously unparsed. Verified live 2026-08-18 against 5 real
  MITRE-bearing rules (SIDs 2001482, 2001485, 2001734, 2002016, 2016781) and against SID
  2100498 (the rule tied to the real captured alert, which has a `metadata:` clause but no
  MITRE keys — the common case). `mitre_technique_id` feeds `mitre_attack`; `mitre_tactic_name`
  normalises to ATT&CK's hyphenated-lowercase shortname (`Defense_Evasion` ->
  `defense-evasion`) and feeds `mitre_tactics` — both the same lists Sigma populates, so
  Stage 2/3 never needs to know which engine a technique came from. `signature_severity`
  (Suricata's own Informational/Minor/Major/Critical scale) maps onto `RuleContext.level`'s
  existing lowercase vocabulary (informational/low/high/critical). Everything else in the
  clause (`mitre_tactic_id`, `mitre_technique_name`, `attack_target`, `deployment`,
  `created_at`, `updated_at`) has no typed field yet, so it lands in `other_tags` labeled
  `key:value` rather than being discarded — same convention `_normalise_sigma_tags` uses for
  unrecognised Sigma tags.
- Real fixtures added: `tests/fixtures/suricata-alert-real.json` (the alert itself, SID
  2100498, `real_suricata_alert_source` in conftest.py), `tests/fixtures/
  so_detection_2100498.json` (that rule's so-detection doc — metadata clause, no MITRE) and
  `tests/fixtures/so_detection_suricata_mitre_real.json` (SID 2001482 — metadata clause WITH
  MITRE). `TestRealSuricataPath` (test_alert_builder.py) and `TestSuricataMetadataParsing` /
  `TestAgainstRealSuricataResponse` (test_detection_rules.py) exercise them; all new logic was
  mutation-checked (breaking the metadata regex and the `event_dataset` fallback both turn the
  relevant tests red).
- YARA (`language="yara"`) is still deliberately unparsed. Checked live 2026-08-18: 0 of
  4,321 real YARA rule bodies in this deployment contain any MITRE reference at all (their
  `meta:` block carries `author`/`description`/`reference`/`date`/`score`/hash fields
  instead), and no `strelka.*` index of any kind exists — Strelka/YARA file-scanning has
  never run here. There is neither data to extract nor an alert path to verify a parser
  against, so building one now would be speculative work against a format with nothing in it.

**The gap this doesn't close — and the more fundamental one.** `config.ES_ALERTS_INDEX`
(`logs-detections.alerts-so*`, the index this repo's whole alert-consumption chain assumes
n8n forwards from) is confirmed live **100% `event.module=sigma`, 0% Suricata/YARA** — not
"no Suricata alert has ever fired" (that was true once, no longer is: `logs-suricata.
alerts-so` now holds 39,949 real fired alerts, including one from 2026-08-18, same rule as
the fixture above). `so-alert-reference/securityonion-es.py` (tier 4, Security Onion's own
Sigma-match alerter, the *only* writer of `logs-detections.alerts-so`) proves why: it's
elastalert's Sigma-match alerter specifically, requiring a `sigma_level` built from a Sigma
rule match. There is no equivalent bridge from Suricata's own native alert output into that
index under stock Security Onion. **So today, a real Suricata alert has no route into the
index this pipeline reads from, independent of anything in this Python codebase.** The work
above (event_dataset, the metadata parser) is necessary but not sufficient for a real
Suricata alert to ever reach `/triage` — closing that needs an n8n-side watcher on
`logs-suricata.alerts-so`, or a Suricata-to-`detections.alerts-so` bridge, neither of which
exists yet. That's a workflow decision for whoever owns the n8n side, not a Python change.

### iTop asset/impact context is structurally unreachable for Suricata alerts

`tools/itop.py::itop_asset_lookup` is hostname/asset_number-keyed only — its own docstring
states IP is **not** a usable lookup key on this iTop instance (no `IPv4Address` class,
`managementip` blank on every object). Suricata alerts have no hostname at all, only
source/destination IPs (confirmed on the real fixture above). So even with a fully populated
production iTop, a Suricata alert gets **zero** impact-dimension asset context from this tool
— not a bug to fix in code, a structural limitation of the hostname-only lookup key. No crash
risk (`_guarded` in `nodes/gather.py` plus the tool's own never-raises contract cover it —
degrades to `AssetContext(found=False)`), but worth recording so a future session doesn't
mistake it for a data-population problem that "fixes itself" once iTop has real records — it
does not, for this alert type, without either an IP-to-asset resolution step or an
IP-capable iTop extension. Neither is built; out of scope for this pass.

### Gap-catalogue Phase 1 — schema/gate fixes, 2026-08-19

Four low-risk items from the 15-item gap catalogue (`resume.md`), closed per the approved
plan (`~/.claude/plans/is-there-an-sqlite-melodic-globe.md`):

- **Gap #2 — `ProcessEvent.integrity_level`/`.elevation_level`.** Added to
  `schemas/evidence.py`, wired in `tools/elasticsearch.py::elasticsearch_process_history`
  reading `process.Ext.token.{integrity_level_name,elevation_level}`. **Tier 1** — the real
  captured fixture (`tests/fixtures/es_process_history_real.json`) has this populated on 2
  of 5 hits and absent on the other 3; both cases are asserted directly against the real
  data, no synthetic fixture needed.
- **Gap #3 — CVE retrieval gate re-enabled.** `nodes/rag.py::_has_cve_indicators` no longer
  hardcoded `False` — now returns `_extract_product_hint(evidence) is not None`, reusing the
  already-correct, previously-dead-code heuristic. **Tier 1 regression-verified**: the real
  Sigma fixture (Microsoft-signed) still resolves to `False`, unchanged behavior; a synthetic
  third-party-signer case now resolves `True` and reaches `retrieve_cve` end-to-end (proven
  via the full `rag_enrichment` orchestration, not just the gate function in isolation).
- **Gap #5 (network half) — `Network.community_id`.** Added to `schemas/alert.py`, wired in
  both `alert_builder.py::_extract_network_from_raw_alert` (Suricata, top-level
  `network.community_id`) and `_extract_network_from_event_data` (Sysmon
  network_connection, nested `event_data.network.community_id`). **Suricata path is tier 1**
  — `tests/fixtures/suricata-alert-real.json` has this populated
  (`"1:4VUkJupYhA6RP+xhGL5c62H+GNQ="`), confirmed via direct fixture inspection before
  wiring, not assumed from the template inventory alone. **Sysmon path remains tier 3/
  synthetic** — no real Sysmon network_connection alert has been captured in this
  deployment yet; upgrade trigger is the same "one real example" gate used throughout this
  repo, not a data-volume threshold.
- **Gap #4 — domain/URL correlation, scope note only, no code change.**
  `tools/elasticsearch.py`'s existing 0%-population finding is confirmed still correct for
  `ES_ALERTS_INDEX` — the docstring now states explicitly that this says nothing about
  `logs-suricata.alerts-so` (a separate index with 39,949 real Suricata alerts, never
  probed), and that re-probing is moot until Suricata alerts have an ingestion path into
  `ES_ALERTS_INDEX` at all (a workflow-level gap, not a code gap in this file).

All four mutation-tested (field path broken, confirmed the relevant test goes red, restored).
`python3 -m pytest tests/ -q` — 349 passed (up from 342; one pre-existing unrelated flaky
timing test in `test_fp_tracking.py` reproduced once under load, passed clean on rerun,
same as previously documented — not caused by this phase's changes).

Phases 2–4 of the same plan (Strelka/Registry schema, Sysmon dispatch-key fix, Suricata
flow-correlation tool) are designed but not yet built — see the plan file for the full
phase breakdown and live-verification prerequisites each one carries.

### Gap-catalogue Phase 2 — Strelka/Registry schema, template-verified, 2026-08-19

- **Gap #7 — `File`/`HashBundle` Strelka fields.** Added `entropy`, `pe_image_version`,
  `pe_flags`, `created`, `accessed`, `mtime`, `ctime`, `mode` to `File`; `ssdeep` to
  `HashBundle`. Wired in `alert_builder.py::_extract_file_from_raw_alert` (reads a new
  top-level `raw_alert.scan.{entropy.entropy,pe.image_version,pe.flags}` object, sibling of
  `file`, plus the existing `file.*`/`hash.*` dicts for the rest). `_merge_hashes` updated
  to carry `ssdeep` through to `observables.hashes` — this was caught by the test suite
  (first run had `ssdeep` silently dropped at the merge step) and fixed before landing.
  **Tier 3, SYNTHETIC COVERAGE ONLY** — no real Strelka alert exists in this deployment
  (sensor not enabled, gap #13); the synthetic fixture is labeled accordingly. One
  correction carried over from the template inventory: no dedicated YARA match-score field
  exists in the resolved schema (`rule.score` was a prior assumption that doesn't hold) —
  none was added; `MalwareVerdict.matches` already covers the rule-identity list.
- **Gap #8a — `Registry` model.** New model in `schemas/alert.py`
  (`hive`/`key`/`path`/`value`/`data`, tier 3 via the shared `registry-mappings` component),
  attached as `CanonicalAlert.registry`. **Schema-only** — no extractor wired yet. Wiring
  one now would risk firing on the wrong Sysmon event type, since gap #10 (Sysmon dispatch
  keys off a field that's constant regardless of event type) isn't fixed yet — that's
  Phase 3 of the same plan, a hard prerequisite, not a stylistic ordering choice.

`python3 -m pytest tests/ -q` — 354 passed (up from 349). All new extraction paths
mutation-tested (field path broken, confirmed relevant test red, restored), including the
`ssdeep`/`_merge_hashes` fix caught mid-phase.

**Note on gap #5's other half**: the approved plan's Phase 1 only covered `Network.
community_id` ("network half" of gap #5). Process PE metadata (`description`/`product`/
`company`, the original other half of gap #5 per `resume.md`) was not included in any
phase of the approved plan — an omission in the plan itself, not a deferral decision. Field
paths are already tier-3 confirmed (`TEMPLATE-SCHEMA-REFERENCE.md` §4, same
`process-mappings`/`dtc-process-mappings` component family Strelka's PE fields above come
from) but need one more live check per that section before calling them fully verified
(Endpoint/Sysmon's `@package` mapping isn't resolvable from the static template export).
Not built in this pass — flagged for the user to fold into a future phase or a standalone
addendum.

### Gap-catalogue Phase 3 — Sysmon dispatch fix + PE metadata, live-verified, 2026-08-19

**Live verification (3a)** against `config.ES_ALERTS_INDEX`, real Sysmon-sourced docs:
`event_data.event.code` (int) reliably distinguishes event types on real data — `1`
(ProcessCreate), `11` (FileCreate), `13` (RegistryEvent: Value Set) all observed among 400
real docs. No pipe (17/18) or WMI (19-21) codes appeared. Two new real fixtures captured
and added: `tests/fixtures/sysmon-registry-alert-real.json` ("Potential Persistence Via
GlobalFlags", nanodump.x64.exe touching `HKLM\...\lsass.exe\GlobalFlags`) and
`tests/fixtures/sysmon-powershell-pe-alert-real.json` ("Potentially Suspicious Powershell
Script Execution From Temp Folder", 88 real matches in this deployment).

- **Gap #10 resolved — turned out simpler than scoped.** No event-code dispatch table was
  needed. `event_data.registry` is a distinctly-named key absent on every other Sysmon event
  shape, so its own presence is an unambiguous signal — the exact same presence-guarded
  pattern every other extractor in `alert_builder.py` already uses
  (`_extract_file_from_event_data`, `_extract_dll_from_event_data`, etc.). New
  `_extract_registry_from_event_data`, called unconditionally alongside the others. Registry
  extraction is now **tier 1** (upgraded from Phase 2's schema-only/tier-3 state) —
  `hive`/`key`/`path`/`value`/`data` (via `data.strings`, joined) all confirmed on the real
  fixture above. `data.bytes` (binary-valued registry data) remains untested — this real
  example was a `strings`-typed DWORD.
- **Gap #5, Process half — the omission flagged after Phase 2, now closed.** Added
  `description`/`product`/`company`/`file_version`/`architecture` to `Process`
  (`schemas/alert.py`), wired in `_extract_process_from_event_data` (same `pe` dict already
  read for `imphash`/`original_file_name`, so this is additive, not a new read path). **Tier
  1** — `description`/`product`/`company`/`file_version` all confirmed populated on the real
  PowerShell fixture; `architecture` stays tier 3, not observed on this one example.
- **Gap #11 — collision guard, now backed by a live citation instead of a hypothetical.**
  The real registry fixture has `event_data.rule = {"name": "T1183,IFEO"}` (Sysmon's own
  internal RuleName config tag) while the actual fired Sigma rule is the top-level
  `rule.name`, `"Potential Persistence Via GlobalFlags"` — confirms this collision is real,
  not speculative. `_parse_rule`'s docstring now cites this example explicitly; a regression
  test (`test_rule_identity_not_confused_with_sysmon_internal_rule_name`) asserts the correct
  value and was mutation-tested by simulating the wrong read order.
- **Also confirmed**: `event_data.process` is present and correctly extracted even on a
  registry-shaped alert (the process that touched the registry) — no dispatch exclusivity
  between process and registry extraction; both fire from the same `event_data` independently.

`python3 -m pytest tests/ -q` — 357 passed (up from 354). All three new/changed extraction
paths mutation-tested, including the collision guard (simulated the wrong field-read
priority, confirmed the regression test catches it).

**Still deferred**: `Pipe`/`Wmi` models — no real example of either event type has fired in
this deployment yet (0 of 400 real Sysmon docs), and no template component resolves their
field paths either (see `TEMPLATE-SCHEMA-REFERENCE.md` §4). Genuinely blocked on a real
example arriving, not on any further live-verification step available today.

### Gap-catalogue Phase 4 — skipped by user decision, 2026-08-19

The Suricata flow-correlation tool (gap #6) was designed (see the plan file) but explicitly
**not built** — user decision to wait until `logs-suricata-so` (or wherever Suricata's
fuller EVE-log output eventually lands) actually has data, rather than shipping a tool whose
only test today would be an empty-index response shape. This closes out the active
implementation portion of the approved gap-catalogue plan: **Phases 1-3 built and tested
(357 passing tests, up from the pre-session 342), Phase 4 deferred by choice, not
blocked.** Remaining open items (`Pipe`/`Wmi` models, Wazuh/OSSEC/logscan engine detection,
TheHive `similarCases`, the `merge_into_case_id` fix) are tracked in `resume.md` and the
plan file for whenever picked back up.

### Gap #12 — TheHive `similarCases` refactor, 2026-08-19

`tools/thehive.py`'s `search_open_cases_by_entities` and `search_closed_cases_by_rule` now
try TheHive's native `getAlert -> similarCases` query stage first (new
`_fetch_similar_cases`/`_closed_cases_via_similar` helpers), falling back to the original
hand-rolled `listObservable -> case` traversal on any failure or when no `thehive_alert_id`
is given — purely additive, never a new failure mode. **Live-verified during planning and
implementation** (real read-only queries against the live TheHive backend via this
codebase's own `_query` helper, not just the MCP wrapper): one round trip now returns
`similarObservableCount` (an overlap-strength number the old code had no equivalent for) and
`linkedWith` (the overlapping observable values), eliminating the old code's separate
per-case `_fetch_case_observables` round trip entirely for cases reached this way.

`ShallowCase` gained `similar_observable_count: int | None` (`schemas/evidence.py`),
populated only on the new path. `nodes/gather.py` now threads `alert.thehive_alert_id`
through both call sites. `search_closed_cases_by_rule`'s rule-tag-based matching (the
`rule:<name>` tag query) is **unchanged** — `similarCases` has no rule-tag concept, so it
only replaces the observable-matching half.

New real fixture: `tests/fixtures/thehive_similar_cases_real.json` — the real
`getAlert(~4661456) -> similarCases` response (2 real closed cases, one of which — `~8613944`
— is the same case ID from this file's already-documented `merge_into_case_id` bug,
confirming it's a real, correctly-matched case). One synthetic row
(`SYNTHETIC_SIMILAR_OPEN_ROW` in `tests/test_thehive.py`) proves the open/inclusion side of
the stage filter, since the real fixture's only examples are both closed.

10 new tests across `tests/test_thehive.py` and `tests/test_gather.py`. Both stage filters
(`stage != "Closed"` for open, `stage == "Closed"` for closed) and the fallback-dispatch
condition were mutation-tested — each confirmed to flip the relevant tests red when inverted,
then restored. `python3 -m pytest tests/ -q` — 367 passed (up from 357).

### Gap #17 — `elasticsearch_related_alerts` engine-branched (Sigma vs. Suricata), 2026-08-21

**Confirmed the day-of via a live field census** (254k+ real docs in `logs-suricata.alerts-so*`,
growing): `elasticsearch_related_alerts` was hardcoded to Sigma's document shape —
always queried `config.ES_ALERTS_INDEX` (100% Sigma) via `event_data.host.name` /
`event_data.user.name` / `event_data.related.{ip,hash}`, fields that only exist inside
Sigma's `event_data` wrapper. For a Suricata-sourced `CanonicalAlert` (no `event_data`, no
`host`/`user` at all) this silently returned `([], None)` — no `Gap` logged — whenever any
IOC IP was present, since the `should` clause list was non-empty and the query legitimately
executed against an index that structurally can never match. A real bug, independent of and
in addition to the already-documented ingestion-path gap (a real Suricata alert still has no
route into `/triage` at all — see the "Suricata alert support" section above; that part
remains an n8n/workflow-level gap, not fixable here).

**Fix**: `tools/elasticsearch.py::elasticsearch_related_alerts` now takes `network:
Network | None` and `investigation_profile: str` and dispatches — `"endpoint_behavior"` ->
`_related_alerts_sigma` (the original, unchanged logic, against `ES_ALERTS_INDEX`);
`"network_threat"` -> new `_related_alerts_suricata`, against new `config.
ES_SURICATA_ALERTS_INDEX` (`logs-suricata.alerts-so*`), correlating via
`network.community_id` / `source.ip` / `destination.ip` — all three tier-1 confirmed
100%-populated across the real index. Any other profile (`malicious_file`, `generic`)
returns an explicit `Gap` naming the unsupported profile rather than guessing a query for a
document shape with no live example to verify against (per implementation guide §2/§0.1).
`nodes/gather.py`'s call site now passes `alert.network` and `alert.investigation_profile`
through — the first real use of `InvestigationProfile` for tool dispatch since the field was
introduced (gap #19; everything else in `gather.py`/`rag.py` still runs the identical fixed
tool set regardless of engine — still open).

**Live-verified three ways**, not just unit-tested: (1) the new Suricata query run directly
against the live cluster by a real, currently-firing `community_id` (SID 2031297, the GORAT
rule), returning 50 real hits, parsed cleanly into `AlertSummary`; (2) the full path exercised
end-to-end — `alert_builder.build_canonical_alert` on the real captured Suricata fixture ->
`investigation_profile="network_threat"`, `Network` fully populated -> fed straight into the
fixed tool, dispatches correctly, returns `(0 results, no Gap)` for that fixture's (older,
different-IP-range) `community_id`, an honest "checked, not found" result; (3) the existing
`test_gather.py::test_live_against_real_backends` (real Sigma alert, all real backends)
still passes unmodified — confirms the Sigma path is genuinely unchanged, not just re-tested.

**New real fixture**: `tests/fixtures/es_related_alerts_suricata_real.json` — captured live
2026-08-21, first 3 of 50 real hits, with `message` and `network.data` stripped (pure
duplicates of already-structured fields, not read by any code) but `dns.query_name` kept
deliberately: sampled across the original 5 captured hits it was IDENTICAL on every one —
confirming it is the firing rule's own static `content:` match bytes, not per-alert DNS data,
a trap now documented in `tools/elasticsearch.py`'s module docstring and regression-guarded
by `TestRelatedAlertsSuricataAgainstRealCapturedResponse::
test_dns_query_name_trap_is_present_but_never_read`. Do not wire this field into any future
domain/URL correlation — see gap #18/#4's finding that no real DNS/HTTP/TLS field is
populated anywhere in this deployment today (Suricata is alert-only, not full EVE firehose).

13 new tests in `tests/test_elasticsearch.py`; the dispatch branch was mutation-tested
(swapped which helper each profile routes to — 24 of the file's tests flipped red, confirming
the new Suricata tests actually exercise the new path and aren't vacuous). `python3 -m pytest
tests/ -q` — 380 passed (up from 367).

### Stage 4 — Analyst Agent built, 2026-08-21

`nodes/analyze.py` (`analyst_verdict`), `schemas/verdict.py` (`TriageVerdict`), and
`prompts/analyst_agent.py` now exist — the second and LAST of exactly 2 LLM calls the whole
pipeline is allowed (CLAUDE.md hard constraint) is built. Mirrors `nodes/context.py`/
`prompts/context_agent.py`'s already-battle-tested pattern line-for-line: hand-inlined
`response_format: json_schema` (zero `$defs`/`$ref`, same reasoning as Stage 3's write-up
above), `_extract_first_json_object`'s defensive first-JSON-only parse (duplicated rather
than imported from `nodes.context` — two parallel/independent stage files, a 2-line helper
isn't worth a cross-node dependency), and a deterministic `_stage_4_fallback` matching
architecture §9's worked example verbatim.

**The one genuinely new piece**: `prompts/analyst_agent.py::_summarize_evidence` — the
"prompt injection firewall" architecture §9 specifies. Stage 4 sees a sanitized summary
(`rule_context`/`asset_context` pass-through, `threat_intel` per-`CortexResult` entry with
`details` truncated to 300 chars, `temporal_context`/`historical_context` as counts,
Stage 3's `mitre_mapping`/`investigation_gaps`/`contextual_modifiers` pass-through) — never
raw log lines, full command lines, or untruncated Cortex report bodies. Returns a plain
`dict`, not a new schema model — it never crosses a stage boundary (Stage 4's real, fully
typed contract is `(ContextualAssessment, EnrichedEvidence) -> TriageVerdict`), matching
Stage 3's own `build_user_prompt` precedent of not inventing an intermediate model for a
pure rendering detail. One resolved discrepancy: architecture's worked `threat_intel` entry
example includes a `score` field — dropped, since `CortexResult` carries no number by hard
constraint (an earlier `alert_builder.py` revision did exactly this and was reverted — see
`CortexResult`'s own docstring).

**`recommended_action`'s enum is dynamically constrained per call**, mirroring Stage 3's
`merge_into_case_id` fix exactly: `correlation_decision.action` is `Literal["new","merge"]`
(exhaustive), and `create_case` only makes sense for `"new"` while `merge_quiet`/
`merge_and_retier` only make sense for `"merge"` (architecture §3's n8n switch treats these
as mutually exclusive branches). `build_triage_verdict_schema` excludes the wrong branch's
options from the enum sent to the LLM; `nodes/analyze.py::_validate_recommended_action` is
the same defense-in-depth backstop `_validate_merge_target` is for Stage 3, in case schema
enforcement doesn't hold — logs and falls back to `needs_review` rather than appending a
gap note (`TriageVerdict` has no gap-list field, unlike `ContextualAssessment` — a
deliberate, documented minor deviation from the Stage 3 pattern, not an oversight).

`impact_if_true`'s 4-tier vocabulary (`minor/moderate/significant/severe`) is a judgment
call, not doc-literal — architecture §9's worked example only ever shows `"severe"`. Chosen
ascending and parallel to `likelihood`'s doc-confirmed 4-tier shape, documented as such per
the same "architecture right on intent, silent on the specific" precedent CLAUDE.md's
ground-truth hierarchy already applies twice elsewhere.

**Live-verified three ways, not just unit-tested**: (1) `.env`'s `STAGE_4_LLM_TIMEOUT` was
bumped to 600 first — it had no override and was sitting on `config.py`'s 180s default,
which Stage 3's own 271.1s/323.2s precedent on this CPU-bound host made a near-certain
mid-call timeout; (2) the first live Stage 4 call ever made in this repo — real
`gather_evidence`+`rag_enrichment` output for the xordump/Invoke-WebRequest alert, paired
with the real `ContextualAssessment` already captured in
`tests/fixtures/context_live_run_fixed_real.json` (reused rather than re-running Stage 3, a
redundant ~300s CPU call for a fixture whose only job is exercising Stage 4) — completed in
**81.2s** (well under the new timeout, faster than Stage 3 since the summarized prompt is
~3.4KB vs. Stage 3's full-evidence dump), produced a clean, sensible
`verdict="needs_review"` with the enum correctly constrained to
`["create_case","close_fp","needs_review"]` (the real `correlation_decision.action` was
`"new"`) and no intervention needed from `_validate_recommended_action`; (3) the fallback
path was deliberately triggered live (pointing `LLM_ANALYZE_BASE_URL` at an unreachable
port, per implementation guide §5) — **0.162s**, exact architecture §9 fallback values,
non-crashing. Both real runs captured to `tests/fixtures/analyze_live_run_real.json` with
full provenance.

27 new tests in `tests/test_analyze.py`, mirroring `tests/test_context.py`'s class
structure. Both `_validate_recommended_action`'s condition and
`_extract_first_json_object`'s `raw_decode` call were mutation-tested (broken, confirmed
the relevant tests flip red — 3 and 2 respectively — then restored). `python3 -m pytest
tests/ -q` — 407 passed (up from 380). One pre-existing, already-documented flaky timing
test in `test_fp_tracking.py` (SQLite writes racing a 0.1s `STAGE_1_TOOL_TIMEOUT_FP`)
reproduced twice during this session under the added load of the new suite, on a different
test each time, same root cause both times, clean on immediate rerun both times — not
caused by anything in this build, same behavior already on record from a prior session.

**Not built by this pass, still open**: Stage 5 (`scoring.py` — takes `TriageVerdict` +
`ContextualAssessment` + `RawEvidence` and produces the final 0-100 score;
`scoring_config.py` already has every constant waiting), Stage 6 (audit/feedback), and the
`/triage` HTTP entrypoint (`main.py`) that would call Stage 0 → 6 in sequence for a real
alert. Nothing currently does that end-to-end call except the ad-hoc verification script
used for this pass's live runs.

### Stage 5 — hybrid priority scoring built, 2026-08-21

`scoring.py` (pure functions: `compute_base_priority`, `apply_llm_modifiers`,
`compute_final_priority`), `nodes/score.py` (`priority_scoring`, the Stage 5 node), and
`schemas/result.py` (`PriorityScore`, `TriageResult`, `ModifierApplied`) now exist — the
pipeline can go all the way from a `CanonicalAlert` to a scored, prioritized result.
`scoring.py` is synchronous, not `async def` — no I/O happens in it, and an async function
with nothing to await would be decoration, not consistency with the LLM-calling nodes that
actually need it.

**This is the ONLY place a number is computed, per the hard constraint** — `alert_builder.py`
and Stage 3/4 stay neutral by design. Both deferred requirements from the table this section
replaces are now wired: `rule_status_penalty` (day-one FP signal from `RuleContext.status`)
and `ContextualAssessment.llm_criticality_score` as the fourth weighted, augmenting formula
component, dividing by the weight sum so the result stays in 0-1.

**Three places architecture §10's literal formula referenced data that turned out not to
exist, each redesigned against the real shape (documented at length in `scoring_config.py`
at each redesign site, not silently ported):**

1. `long_term_fp_rate` doesn't exist — `FPSignal` reports two independent 30-day COUNTS
   (`tools/fp_tracking.py`'s deployment decision), no rate denominator. Redesigned as a
   saturating `min(1.0, count / FP_COUNT_SATURATION_CAP)` pseudo-rate, `max()` of the
   rule-scoped and host-scoped proxies (either alone at full strength is meaningful; a sum
   or average would under-penalize a rule that's a known problem on one host).
2. `technique.priority_0_5` doesn't exist on any of the 697 real `mitre_techniques` Qdrant
   points (`MitreCandidate`'s own docstring, live-verified 2026-08-16) — `mitre_technique_
   severity` is computed from ATT&CK TACTIC instead (kill-chain-position severity, `discovery`
   low through `impact`/`exfiltration` high), the one MITRE dimension every real source
   (`RuleContext.mitre_tactics`, Stage 3's `refined_mitre_mapping[].tactic`) actually carries.
   Falls back from the refined mapping to `rule_context.mitre_tactics` when Stage 3's own
   fallback has zeroed out `tactic` (`nodes/context.py::_stage_3_fallback` sets `tactic=""`
   on every entry) — a downed LLM must not silently zero the impact term the way v3's
   severity-cap bug did. Mutation-tested: deleting the fallback branch flips a test red.
3. `evidence_age_hours`'s timestamp ambiguity — SESSION-FINDINGS.md's open item 4.5.6, never
   resolved until now. Resolved to `CanonicalAlert.timestamp` (the SO alert's own detection
   time — how old the investigation is), not the underlying triggering event's timestamp
   (which can differ by days per that finding).

`evidence_completeness_pct` is deliberately NOT the same signal as `gap_count` (both appear
as separate terms in §10's confidence formula) — completeness measures how much
`CanonicalAlert` itself extracted about the alert (host/user/process/network/file/IOC/cortex
presence, 8 fields), gap_count measures how many Stage 1 TOOL calls produced a `Gap`;
computing both from the same signal would double-penalize it under two names.

**Live-verified against real data, not just unit-tested**: ran `nodes.score.priority_scoring`
against real, freshly-gathered `EnrichedEvidence` (the xordump alert, real `gather_evidence`
+ `rag_enrichment`) paired with the real captured `ContextualAssessment` and `TriageVerdict`
from this session's Stage 3/4 fixtures. Every intermediate value was hand-verified against
the real evidence before the test suite was written: `rule_severity_score=70` (level=high),
`rule_status_penalty=-10` (status=test), `asset_criticality_score=95` (iTop criticality=high),
`mitre_technique_severity=65` (max of execution/55, command-and-control/65),
`base_confidence=25` (evidence_completeness 50% − 4 gaps×10 + 0 + source_reliability 15) →
confidence gate correctly fired and escalated the P2 score (69) to **P1**. Captured to
`tests/fixtures/score_live_run_real.json`.

93 new tests in `tests/test_scoring.py`. Mutation-tested 4 guards (the per-dimension modifier
cap, the MITRE-tactic fallback, the confidence-gate escalation, the priority-band boundary
comparison) — 3 were caught on the first pass; the confidence-gate mutation **survived**
initially because the test only asserted the boolean flag, not that escalation actually
changed the priority band. Fixed the test to assert `result["priority"] ==
_escalate_priority(unescalated)`, re-ran the mutation, confirmed it now goes red, restored.
Left in as `test_confidence_gate_escalates_priority`'s own docstring — this repo's fixture
discipline exists precisely to catch tests that pass for the wrong reason, and this was a live
example of it working. `python3 -m pytest tests/ -q` — 500 passed (up from 407).

**Not built by this pass, still open**: Stage 6 (audit/feedback — `tools/fp_tracking.py::
record_triage_outcome` exists and is callable, just never called from a Stage 6 node), and the
`/triage` HTTP entrypoint (`main.py`) that would call Stage 0 → 5 in sequence for a real alert.

### Case action — this service now writes to TheHive directly, 2026-08-21

**Deliberate deviation from architecture §1/§3.** The original design is read-only by
construction — "Not a full autonomous SOC... every case-modifying action happens in n8n
after human review" (§1), and §3's topology has n8n switch on `TriageResult.
recommended_action` to create/merge cases itself, after `/triage` responds. **User-directed
change, confirmed via explicit clarifying questions before building**: this Python service
now creates or merges the TheHive case ITSELF, and `/triage`'s eventual response is meant to
carry the resulting case id back. Do not "correct" this back toward the read-only design —
it's deliberate, the same way every other deployment-specific decision in this file is.

**Every alert results in a case action, unconditionally — no `needs_review`/`close_fp`
hold-off.** The user was explicit: "must still just create or merge." `nodes/case_action.py
::case_action` is driven ONLY by `context.correlation_decision.action`
(`Literal["new","merge"]`, already exactly this binary) — `TriageVerdict`'s richer fields
(verdict, recommended_action, reasoning, summary, citations) become CONTENT written into the
case (title/description/tags), never a gate on whether to act.
`recommended_action == "merge_and_retier"` is the one place `TriageVerdict` changes
behavior: it triggers an extra severity-bump `update_case` call on top of the merge, since
TheHive's merge endpoint doesn't accept field overrides in the same call.

**New TheHive write endpoints, discovered empirically — none of the conventional-sounding
guesses were right on the first try:**

```
POST /api/v1/alert/{id}/case            create a case from an alert (NOT /promote — 404)
POST /api/v1/alert/{id}/merge/{caseId}  merge an alert into an existing case
PATCH /api/v1/case/{id}                 partial update (severity, tags, description, ...)
POST /api/v1/case/{id}/comment          add a comment (NOT /api/v1/comment/case/{id} — 404)
```

`merge`'s path was confirmed correct via a real HTTP **400** ("Alert is already imported")
on an already-merged alert — a business-logic error proves the routing is right; a 404 would
have meant the path itself was wrong. `create_case_from_alert` is TWO calls, not one: the
create endpoint's empty-body response uses the ALERT's own title/severity/tags as defaults,
and there was no second real alert left in this deployment (only 3 existed total, all three
consumed during endpoint discovery) to verify whether that same endpoint also accepts
content overrides directly — so `create_case_from_alert` always follows up with the
independently-verified `PATCH` instead of trusting an unconfirmed shortcut.

**Live-verified, all real, 2026-08-21** (`tools/thehive.py`'s and `nodes/case_action.py`'s
own module docstrings carry the full account): `update_case` and `add_case_comment`
succeeded for real against the disposable test case `~8609848`; `merge_alert_into_case`
failed for real with the exact "already imported" error, both directly and again through the
full `case_action` node end-to-end (`tests/fixtures/case_action_live_run_real.json`); the
`action=="new"` dispatch branch was run live against a nonexistent alert id (real 404, clean
failure, not captured to a fixture since there's nothing further to regress-guard). One real
case was created: `~4464672` (case #4), from real alert `~4636880`, during endpoint
discovery — visible in TheHive, safe to delete if unwanted.

24 new tests in `tests/test_case_action.py`. Three dispatch conditions mutation-tested (the
new/merge branch selection, the null-merge-target defensive fallback, the
`merge_and_retier` extra-update gate) — all three confirmed to flip red when broken, then
restored. `python3 -m pytest tests/ -q` — 524 passed (up from 500).

**Not yet done**: `TriageResult.case_action` is a field that exists and gets populated by
whoever calls both `nodes/score.py::priority_scoring` and `nodes/case_action.py::case_action`
and assigns the result — there is still no orchestrator (`main.py`/`pipeline.py`) that does
this automatically for a real incoming alert. Also still open: what `/triage`'s HTTP response
schema actually looks like end-to-end, and Stage 6's audit/FP-feedback wiring.

### Lifecycle logging built, 2026-08-21

**Before this, there was no logging visibility at all**, despite 12 modules already calling
`logging.getLogger(__name__)` — nothing anywhere called `logging.basicConfig()` or
configured a handler/formatter/level. Python's defaults applied: root at WARNING, a bare
"lastResort" handler, no timestamp, no way to tell which alert a line belonged to. Confirmed
by grep before building anything: almost every existing call was `.warning`/`.error`
(failure paths only) — zero visibility into the happy path at any level, because nothing was
configured to print INFO/DEBUG at all.

**New `logging_config.py`** — `alert_id_var: ContextVar[str]` (not a thread-local: this is
an asyncio codebase, and `ContextVar` is the mechanism that actually propagates through
`await` boundaries and concurrent tasks), a `_AlertIdFilter` that injects it into every log
record, and `alert_context(alert_id)` (a context manager each node wraps its body in).
**Retroactive by design** — installing the filter alone tagged all ~30 pre-existing
`logger.warning`/`.debug` calls across this codebase with the right alert id, with zero
edits to those call sites. `configure_logging()` is idempotent and called automatically from
`nodes/__init__.py` and `tools/__init__.py` — no `main.py` dependency, works for a real run,
an ad-hoc verification script, or pytest alike.

**New config**: `LOG_LEVEL` (default `INFO`), `LOG_FILE` (default `./logs/soc3s.log`, a
`RotatingFileHandler`; empty disables file output — console-only). One correction made
live, not assumed: setting `LOG_LEVEL=DEBUG` initially unmuted `httpcore`/`httpx`/`asyncio`'s
own wire-level DEBUG output, burying the pipeline's own detail in pages of connection-frame
noise — confirmed by actually running it and reading the output, not by inspecting the code.
Fixed by forcing those three loggers to WARNING regardless of `config.LOG_LEVEL`
(`_NOISY_LOGGERS` in `logging_config.py`).

**Single injection point for all per-tool detail**: `nodes/_guard.py`'s `_guarded`/`_skip` —
the shared wrapper every one of Stage 1's 8 tools and Stage 2's 3 Qdrant calls already passes
through — got DEBUG-level entry/exit/duration/outcome logging added ONCE, covering all 11
tool calls with zero edits to any individual `tools/*.py` file. DEBUG, not INFO, so the
default level reads as a per-stage story, not a tool-call firehose.

**Every node** (`gather.py`, `rag.py`, `context.py`, `analyze.py`, `score.py`,
`case_action.py`) wraps its body in `alert_context(...)` and logs an INFO start line plus an
INFO completion line carrying the one diagnostically useful summary for that stage (gap
count; MITRE/incident/CVE match counts; confidence/action/modifier count; verdict/
recommended_action; score/priority/gate; case new-vs-merge/success/case_id). Stage 3 and 4
additionally log the LLM call's own start/end separately from the stage's — the highest-value
addition, since these are the 60–300s+ CPU-bound calls this session's own live runs were
repeatedly the "is it hung or just slow?" question for.

**Live-verified, not just read back**: ran the real Stage 1→2→5→case-action chain (reusing
this session's already-captured real Stage 3/4 fixtures) at `LOG_LEVEL=INFO` — a single
alert id tags every line across all four stages, `WARNING` (opencti's known 301 redirect gap,
case_action's expected no-thehive_alert_id failure) interleaves correctly with the INFO
narrative, and dropping to `LOG_LEVEL=WARNING` silences everything but those two failures, as
designed. `./logs/soc3s.log` confirmed to receive identical content to the console.
`python3 -m pytest tests/ -q` — still 524 passed, confirming the new import-time
`configure_logging()` call doesn't break, slow, or duplicate output in the existing suite
(a real, checked risk — pytest has its own log capture — not an assumption).

No new tests — this is observability, not business logic; nothing here changes any
stage's output, only what gets printed alongside it.

### `ExtractedObservable.observable_type`'s "process" renamed to "process-path", 2026-08-21

User-directed: the `process` bucket's items are always an executable path worth actioning on
(block/quarantine) — the type label now says so, `Literal["process-path", "file", "domain",
"url", "ip", "hash"]` (`schemas/assessment.py`). `prompts/context_agent.py::_BUCKET_TO_TYPE`
and the system prompt's TASK 4 wording both updated to match; the dynamic per-bucket enum
constraint (`build_contextual_assessment_schema`) picks the new value up automatically since
it reads `_BUCKET_TO_TYPE[bucket]` rather than a hardcoded literal. Live-confirmed the
rendered schema sent to the LLM now constrains the process bucket to
`{"enum": ["process-path"]}`. One incidental bug caught while writing the prompt wording
change: a literal `"C:\Windows\Temp\xordump.exe"` example inside the non-raw `SYSTEM_PROMPT`
string was parsed by Python as a `\x` hex-escape attempt (`\xor` is not valid hex) and threw
a `SyntaxError` at import time — fixed by escaping the backslashes
(`"C:\\Windows\\Temp\\xordump.exe"`), confirmed the rendered prompt text still shows single
backslashes. `tests/test_context.py`'s two literal `"process"` references (the bucket→type
expectation map, one `ExtractedObservable` construction) updated to `"process-path"`.
`python3 -m pytest tests/ -q` — still 524 passed (a rename, not new coverage).

### Extracted observables are written into the TheHive case, 2026-08-21

**Until this change, `ContextualAssessment.extracted_observables` was a dead output** — the
Stage 3 LLM filled all six buckets and nothing downstream ever read the field.
`nodes/case_action.py` never referenced it; `tools/thehive.py` had no observable-write
function at all (every observable code path in that file was a read). User-directed: all six
buckets now get written onto the case, new or merge alike, and **process-path observables
carry both tags `react` and `malicious`**.

**Stage 3 is untouched by this — deliberately.** `nodes/context.py`,
`prompts/context_agent.py` and `schemas/assessment.py` have zero changes. No `is_malicious`
field was added to `ExtractedObservable` and no third LLM call exists: the tags are attached
deterministically from *which bucket* an item is in, since the process bucket is already
defined in TASK 4 as "the executable's PATH … the thing an analyst would actually block or
quarantine". Being in that bucket already is the judgment. Do not "improve" this by asking
the model for a maliciousness boolean — that adds a second, independently-wrong-able source
of truth for one fact, and the 2-LLM-call constraint is hard.

**New endpoint, live-verified 2026-08-21**: `POST /api/v1/case/{caseId}/observable` → 201,
returning a **list** containing the created observable. Right on the first try, unlike
`/promote` and `/api/v1/comment/case/{id}` before it.

**Bucket → `dataType`**: `process`→`filename`, `file`→`filename`, `external_ips`→`ip`,
`domains`→`domain`, `urls`→`url`, `hash`→`hash`. **`process` and `file` share `filename`, so
the tag decision can NOT be derived from `dataType` — the bucket is the only discriminator.**
A refactor keying the condition off `data_type` would silently tag every file observable
malicious; `test_bucket_not_datatype_decides_the_tags` guards it, backed by a fixture
assertion against real stored data. Second trap: **TheHive returns tags in a different order
than sent** (sent `["react","malicious"]`, stored `["malicious","react"]`) — sort or use a
set, never a positional compare.

**Live-verified twice, and the second one is the one that counts**: (1) raw endpoint probe
confirming path/201/response shape and that a Windows process path is accepted under
`filename`; (2) the **composed** `add_extracted_observables` called for real against
disposable case `~8609848` with all 6 buckets populated — returned `(written=6, gaps=0)`,
then all 6 read back through this repo's own `_fetch_case_observables`/`_query` helpers and
inspected field-by-field, with exactly one observable tagged. Captured with provenance in
`tests/fixtures/thehive_create_observable_real.json`. Before run (2), `"filename"` was only
a tier-4 guess from `mission/n8n-scrpt.py`.

The write is **gated behind create/merge succeeding** on both branches, and is **never a gate
on the node's own success** — observables are additive content on an already-successful case
action, so failures increment `CaseActionResult.observables_failed` (new, with
`observables_written`) and append to `error` while `success` stays `True`. An all-empty
extraction — the common benign-alert outcome — short-circuits to `(0, [])` with zero HTTP
calls and no `Gap`.

`python3 -m pytest tests/ -q` — **547 passed** (up from 524). 23 new tests: 16 in the new
`tests/test_observable_writes.py`, 7 node-wiring tests in `tests/test_case_action.py`. Three
mutations run and each confirmed to flip the relevant tests red before restoring (swapped
`_BUCKET_TO_DATATYPE` entries; wrote against `thehive_alert_id` instead of the created case
id; moved the tag condition to the `file` bucket). The pre-existing `test_fp_tracking.py`
timing flake reproduced once under load and passed clean on rerun, same as previously
documented.

**Not done**: the full `case_action` node was never run end-to-end against live TheHive with
a non-empty extraction — that needs a real un-imported alert, and none has been spare since
endpoint discovery consumed the last of this deployment's three. The node wiring is
mocked-and-mutation-tested, not live-proven. Alert-level observable writes and bulk creation
were never probed. See `pipeline_v1.md` §11 for the full account.

### LLM backend swapped to vLLM/Colab (temporary test session), 2026-08-23

**Both Stage 3 and Stage 4 pointed at a vLLM server on a Colab T4 GPU** (`foundation-sec-reasoning`,
8-bit bitsandbytes, `--dtype float16`, `--max-model-len 8192`), reached through a cloudflared
tunnel — `.env`'s `LLM_BASE_URL`/`LLM_API_KEY`/`LLM_MODEL` updated accordingly, no
`LLM_ANALYZE_*` override (both stages share the endpoint, same as the Ollama deployment this
temporarily replaces). This is a temporary test session, not a permanent deployment decision —
the tunnel URL and key are only valid while that Colab runtime stays alive; **do not treat this
as the new `LLM_BASE_URL` default** once that runtime ends.

**Live-verified end-to-end** (real `gather_evidence`+`rag_enrichment` against real backends for
the xordump alert, then one real Stage 3 call and one real Stage 4 call against vLLM, no
mocking): preflight `GET /v1/models` confirmed `max_model_len: 8192` directly from the server.
Stage 3: 76.0s wall clock, `usage.prompt_tokens=2476, completion_tokens=549`, schema validated
cleanly. Stage 4: 34.3s wall clock, `usage.prompt_tokens=1538, completion_tokens=240`, schema
validated cleanly. Both well inside the `max_tokens` budgets (4000/2000) and the 8192 context
window — the concern that `max_tokens` might be tight against a small context window did not
materialize on this alert. Both `nodes/context.py` and `nodes/analyze.py` needed zero code
changes — `response_format: json_schema` with the existing hand-inlined flat schemas (see
`prompts/context_agent.py`/`prompts/analyst_agent.py`'s own docstrings on why they're hand-
inlined for Ollama) worked against vLLM's OpenAI-compatible surface unchanged. Neither raw
response showed a `<think>` block or populated `message.reasoning` — left unexplained; possibly
grammar-constrained decoding under `response_format` suppresses a reasoning preamble entirely,
possibly vLLM's reasoning-parser just isn't wired up for this model/server-args. Not resolved
this session — would need a live A/B (schema-constrained vs. plain `json_object`) to tell which.

### Fixed — `_validate_extracted_observables` JSON-escaping false-discard bug, 2026-08-23

**Found live**, during the vLLM backend-swap test above: all 6 `extracted_observables` entries
in that real Stage 3 response got discarded as "hallucinations." 5 genuinely were fabricated
(`evil.com`, `192.168.1.1`, a fictional hash — none of that exists anywhere in this alert's
evidence). The 6th, the `process` bucket's `C:\Windows\Temp\xordump.exe`, is the alert's real
`-OutFile` path from its actual PowerShell command line — a correct extraction, wrongly
discarded.

**Root cause**: `nodes/context.py::_validate_extracted_observables`'s hallucination check did
`if item.value not in evidence_json:`, where `evidence_json = evidence.model_dump_json()`.
`item.value` is unescaped (already JSON-decoded from the LLM's response — a genuine Windows
path has one backslash per separator). `evidence_json` is JSON *text*, where Pydantic's
serializer has already escaped every `\` as `\\` and every `"` as `\"` — required by the JSON
spec, since a bare `\` in JSON text always starts an escape sequence. So the check compared an
unescaped needle against an escaped haystack: any genuinely-correct value containing a
backslash or quote — i.e. every Windows path, exactly what the `process`/`file` buckets exist
for — always failed this check, regardless of correctness. Reproduced and confirmed in
isolation (a real value present in a serialized evidence dict still fails `in` after JSON
escaping; round-tripping the JSON text back through `json.loads()` collapses the doubled
backslashes right back to the original single-backslash value, proving the doubling is real
JSON-escaping mechanics, not a display artifact). Confirmed via a scoping check that this is
the *only* place in the repo with this anti-pattern (no other `nodes/*.py`/`tools/*.py`/
`prompts/*.py` file does a substring check of a plain string against JSON-serialized Pydantic
output), and that Pydantic 2.13.4's `model_dump_json()` emits raw UTF-8 for non-ASCII rather
than `\uXXXX`-escaping it (`ensure_ascii=False` behavior) — relevant to the fix below.

**Fix**: escape the needle the same way before comparing —
`needle = json.dumps(item.value, ensure_ascii=False)[1:-1]`, then `if needle not in
evidence_json:`. `ensure_ascii=False` matters: plain `json.dumps(item.value)` (default
`ensure_ascii=True`) would `\uXXXX`-escape any non-ASCII IOC value and reproduce the same class
of false-discard for e.g. an IDN domain. The existing duplicate-check (`item.value in
known_values`) was untouched — both sides there are already plain Python strings, never
affected by this bug.

**Tests**: 5 new tests in `tests/test_context.py::TestExtractedObservablesValidation` —
backslash-, quote-, and non-ASCII-bearing values that are genuinely in evidence (must be kept),
a backslash-bearing value that genuinely isn't (must still be discarded — proves the fix isn't
"always keep"), and one end-to-end test replaying this session's own real captured vLLM
response verbatim (`tests/fixtures/context_stage3_vllm_escaping_bug_real.json`, REAL —
extracted directly from the live run's raw HTTP response, round-trip-verified against
`_extract_first_json_object` before use) through the actual `context_analysis` coroutine,
confirming the real process-path value is now kept while the same response's 5 genuinely-
fabricated values are still correctly discarded. Mutation-tested twice: reverting the escaping
entirely flips 3 tests red (backslash, quote, real-capture); reverting only `ensure_ascii=False`
flips exactly the non-ASCII test red. Both restored. `python3 -m pytest tests/ -q` — 552 passed
(up from 547).

### Stage 4 expanded — actionable-observables judgment (TASK 5), 2026-08-23

**User-directed, following the vLLM backend-swap test and the escaping-bug fix above.**
Stage 4 previously never saw any observables at all — `prompts/analyst_agent.py`'s
"prompt injection firewall" (`_summarize_evidence`) deliberately excluded both
`canonical_alert.observables` and Stage 3's `extracted_observables`. Both are now
included, plus a new third source — the merge target case's existing observables,
fetched live from TheHive — and Stage 4 (still "the second call"; the 2-LLM-call hard
constraint is untouched) now judges which of all three warrant action.

**New**: `schemas/verdict.py::ActionableObservable` (`observable_type`, `value`,
`recommended_disposition: block|quarantine|monitor`, `reasoning`) and
`TriageVerdict.actionable_observables: list[ActionableObservable]`.
`tools/thehive.py::fetch_case_observables_with_type(case_id, timeout=None) ->
tuple[list[dict], Gap | None]` — additive, NEVER RAISES, reuses the exact
`getCase -> observables -> page` query `_fetch_case_observables` already proves live,
but keeps `dataType`/`tags` instead of collapsing to bare value strings (that private
helper and its one existing caller, `search_open_cases_by_entities`'s enrichment loop,
are untouched). New `config.STAGE_4_TOOL_TIMEOUT_THEHIVE` (5.0s default), distinct
from the Stage-1-scoped constant by name.

**`nodes/analyze.py`**: on `correlation_decision.action == "merge"` with a real
`merge_into_case_id` — resolved in Stage 3's output, confirmed available before Stage 4
runs (`case_action.py` only consumes it, never resolves it) — fetches the target case's
observables directly (no `_guarded` wrapper, same reasoning `nodes/context.py` already
gives for its own single-call LLM request: the function self-times-out and never
raises). On `"new"` or a failed fetch: `case_observables = []`, proceeds — `TriageVerdict`
has no gap-list field, same limitation `_validate_recommended_action` already works
within, log-only.

**New validator, `_validate_actionable_observables`, carries forward today's escaping
fix from the start** — built with the lesson from the `_validate_extracted_observables`
bug above already applied, not discovered again the hard way: every
`actionable_observables[].value` must be traceable to `known_observables ∪
extracted_observables ∪ case_observables` (the exact three sources TASK 5 names in the
prompt — not the full evidence Stage 4 never sees, that firewall boundary is unchanged),
checked via `json.dumps(value, ensure_ascii=False)[1:-1]` against a haystack built with
the same `ensure_ascii=False`. Mutation-tested the same way as the original fix:
reverting the escaping flips exactly the one backslash-bearing test red
(`test_value_traceable_to_extracted_observables_is_kept`), the three plain-string tests
stay green; restored.

**Scoping boundary, deliberate**: `nodes/case_action.py`'s observable-write path is
unchanged — it still writes Stage 3's raw `extracted_observables` to TheHive, tagged
`react`+`malicious` on the process bucket as already built. `actionable_observables` is
additive and response-only for now: Stage 4's judgment surfaced to the eventual `/triage`
caller, not (yet) wired into what gets committed to the case.

**Live-verified twice** (`config.LLM_BASE_URL` pointed at a Colab/vLLM tunnel,
`foundation-sec-reasoning`, same backend as the escaping-bug fix above — the tunnel
rotates across Colab restarts, expect the URL/key in `.env` to go stale between
sessions, as it did mid-session here: first retry hit a `ConnectError` on an expired
tunnel, second hit a `401` from a stale API key after the tunnel came back, third — with
both corrected — succeeded): real `gather_evidence`+`rag_enrichment` for the xordump
alert (`open_cases: []` — confirms this deployment still has no open cases, so the merge/
case-observable-fetch path has no real scenario to exercise yet, same gap Stage 3's own
merge-target fix already noted), real Stage 3 call (79.1s, correctly discarded 6
fabricated `extracted_observables` values as hallucinations — this run's alert
construction didn't populate `process`/`observables` fields, so nothing was genuinely
traceable), real Stage 4 call (45.5s) with the new schema — validated cleanly, returned
`actionable_observables: []`, a correct result given Stage 3 had discarded everything
upstream, not a failure of the new judgment logic. Captured to
`tests/fixtures/analyze_actionable_observables_live_run_real.json`. Confirms the new
field survives vLLM's `response_format: json_schema` grammar constraint without
reproducing the `$defs`/`$ref` hang class of bug (schema is static, zero `$defs` — same
discipline as every other schema in this repo) — did not yet observe a real *populated*
`actionable_observables` example, since no real merge scenario exists and this run's
evidence had nothing left to judge after Stage 3's own hallucination filter ran.

18 new tests (11 landed with the tool function + validator, mirroring
`tests/test_context.py::TestExtractedObservablesValidation`'s structure): `tests/
test_analyze.py::TestActionableObservablesValidation` (4), `::TestCaseObservablesFetch`
(2), plus signature-only updates to `TestSummarizeEvidenceFirewall`'s three existing
tests; `tests/test_thehive.py::TestFetchCaseObservablesWithType` (5). `python3 -m pytest
tests/ -q` — 563 passed (up from 552). Same pre-existing `test_fp_tracking.py` timing
flake reproduced once under load this session, clean on immediate rerun, unrelated to
this change (documented recurring behavior, see prior entries).

### `main.py` built — the `/triage` HTTP orchestrator, 2026-08-23

**User-directed, following the Stage 4 expansion above.** Nothing previously chained
Stage 1→6 for a real incoming alert — every prior session ran individual node functions
by hand. `main.py` is now a FastAPI app (`fastapi` 0.141.1 / `uvicorn` 0.52.0, both
already installed in this environment though no dependency manifest exists in the repo)
exposing `POST /triage` and `GET /health`, matching architecture's file-tree spec.
`POST /feedback` (Stage 6 audit/FP-feedback) stays out of scope — that stage isn't built.

**Synchronous, per explicit user direction** (confirmed via clarifying questions before
building): one blocking request/response per alert, matching architecture's own
deployment checklist ("n8n workflow configured with 300s HTTP timeout on `/triage`").

**Ingestion — the one step n8n's payload doesn't carry.** `AlertWebhookPayload`
(`schemas/alert.py`) is exactly `{thehive_alert_id, raw_alert, asset_context}` — no
`hive_alert`. `main.py` fetches it itself via the already-built, NEVER-RAISES
`tools.thehive.get_full_alert_with_analysis(thehive_alert_id)` before calling
`alert_builder.build_canonical_alert`, per `SOC-3s-IMPLEMENTATION-GUIDE.md` §0.2's
documented sequence.

**Failure posture, user-directed**: HTTP 200 always. `schemas/result.py::TriageResponse`
(`success`, `result: TriageResult | None`, `error`, `failed_stage`) wraps every response.
A `stage` variable is tracked explicitly and updated before each call (not inferred from
a traceback), so `failed_stage` is always accurate; `result` starts `None` and gets
assigned as soon as Stage 5 produces one, so a later failure (e.g. Stage 6) still returns
whatever was already built rather than discarding it. Every node from Stage 1 onward
already had a documented "never raises to caller" contract before this build — the
`try/except` here is a safety net for ingestion and genuine unexpected defects, not a
path expected to fire often in practice.

**`schemas/result.py`**: `TriageResult` gained `likelihood`, `impact_if_true`,
`evidence_citations`, `actionable_observables` (surfacing the rest of `TriageVerdict`'s
detail — previously only `verdict`/`recommended_action`/`summary`/`reasoning` were
flattened here). `nodes/score.py::priority_scoring` already receives the full
`TriageVerdict` as its first argument, so it copies these across at construction time,
same place the original four fields were already being flattened from — no new node
needed, no new node dependency.

**`GET /health`**: deliberately minimal — a reachability check against `LLM_BASE_URL`
only (not ES/TheHive/iTop/Qdrant), 503 on failure. Chosen specifically because it's the
cheapest check that would have caught both of this session's own real `.env` staleness
incidents (a dead tunnel, then a stale API key) immediately rather than only on the next
real alert.

**Live-verified two ways, both real, no mocking**: (1) 6 new tests in
`tests/test_main.py` using FastAPI's `TestClient`, monkeypatching every node at its
`main.py` import site (`main.gather_mod`, `main.rag_mod`, etc. — `main.py` uses the
`import module as x` convention specifically for this, matching `tests/test_gather.py`'s
established pattern, not `from module import func` which would require patching every
call site individually) — a happy-path test, a degraded-hive-alert-fetch test, two
failure-injection tests (mid-pipeline and post-Stage-5 failure, confirming partial
`result` survives), and two `/health` tests. (2) The real thing: started `uvicorn
main:app` as a real subprocess, POSTed a real HTTP request to `http://127.0.0.1:8123/
triage` using `thehive_alert_id=~4636880` — one of this deployment's only 3 real alerts,
already `Imported` (promoted to case `~4464672` during the case-action endpoint-discovery
session, per that section above) — with real ES/TheHive/iTop/OpenCTI/Qdrant/LLM backends,
zero mocking. Result: HTTP 200, 135.2s wall clock, `success: true` end-to-end. Along the
way it exercised nearly every real path in one shot: Stage 1 hit a real OpenCTI 301
redirect gap (handled, non-fatal), Stage 3 correctly resolved `action="merge"` against
the real pre-existing case and correctly discarded 3 extracted observables as
**duplicates** of `canonical_alert.observables` (a different, already-built code path
from the hallucination-discard fix above — confirms both still work), Stage 4's new
case-observable fetch fired silently with no `Gap` logged (a clean ~133ms TheHive round
trip between "Stage 4 started" and the LLM call, confirmed in the server log), Stage 5
produced a full real score breakdown (P3/62), and Stage 6 correctly attempted the real
merge, got TheHive's real `400 "Alert is already imported"` (the same, previously-
documented error class from that session — expected, since this alert already has a
case), and reported it as `case_action.success=False` **without** the outer
`TriageResponse.success` going `false` — proving the intended semantics work for real:
a degraded sub-component doesn't fail the whole response. Captured to
`tests/fixtures/main_triage_live_run_real.json`. No real alert in this deployment is
available un-imported, so this run couldn't prove a fresh `create_case_from_alert`
success end-to-end through `/triage` — that specific path is already independently
live-verified in the case-action section above (case `~4464672`'s original creation);
not re-proven here, not a gap in this build.

`python3 -m pytest tests/ -q` — **569 passed** (up from 563).

### Fixed — Stage 4 now judges EVERY observable (with confidence), Stage 6 writes them and returns real TheHive IDs, 2026-08-23

**User-directed correction to the actionable-observables build above, same day.** Two real
problems in what shipped earlier: (1) `nodes/case_action.py` wrote Stage 3's raw
`extracted_observables` straight to TheHive, never consulting Stage 4's judgment at all —
the whole point of TASK 5 was being skipped. (2) `ActionableObservable` had no confidence
field, and even where TheHive did hand back a real observable `_id` on creation
(`create_case_observable`), the code fetched that response and threw it away, keeping only
a bare `True`/`False`.

**The fix, four pieces:**

1. **`schemas/verdict.py`** — `ActionableObservable` gains `confidence: Literal["high",
   "medium","low"]` (LLM-set, required) and `observable_id: str | None` (never LLM-set —
   filled in by Stage 6 after the real write/lookup, same "set post-hoc" pattern
   `stage_4_duration_ms`/`runbook_matches` already use).
2. **`prompts/analyst_agent.py`** — TASK 5 rewritten: Stage 4 now assesses **every**
   observable across `known_observables`/`extracted_observables`/`case_observables`, not a
   filtered shortlist — a weak signal still gets an entry (`recommended_disposition=
   "monitor"`, `confidence="low"`), nothing is silently dropped for being uncertain. Schema's
   per-item `required` now includes `confidence`.
3. **`tools/thehive.py`** — `create_case_observable` now returns the real assigned
   `_id` (`tuple[str | None, Gap | None]`, was `tuple[bool, Gap | None]`) instead of
   discarding TheHive's response. `fetch_case_observables_with_type` now also keeps each
   row's `_id` (the query already returned it — it just wasn't being copied into the
   output dict). `add_extracted_observables` — the old "write all 6 buckets blindly, no
   dedup" composed function — is retired outright; its only caller is gone.
4. **`nodes/case_action.py`** — new `_write_actionable_observables(case_id,
   actionable_observables)`: after create/merge succeeds (case_id now real either way),
   fetches the case's current observables once, reuses an existing `observable_id` when a
   value already matches (no duplicate write), otherwise creates it and captures the new
   id. Tags now reflect Stage 4's own judgment (`disposition:<value>`, `confidence:<value>`)
   rather than the old blanket `["react","malicious"]` every process-path item used to get
   regardless of actual confidence — that convention doesn't carry over now that low-
   confidence/"monitor" items are written too. `ioc=True` only for block/quarantine.
   `CaseActionResult` gains `actionable_observables_written` (the enriched list);
   `main.py` overwrites `TriageResult.actionable_observables` with it after Stage 6 runs,
   so the final `/triage` response always carries real ids once case_action has completed.

**Live-verified two ways** (same recurring tunnel-rotation pattern this session — the
`.env` credential went stale mid-work again, twice): (1) a full real `POST /triage` through
the persistent service confirmed the "gated behind a successful create/merge" behavior for
real — `~4636880`'s merge into `~4464672` failed with the same, already-documented real
"already imported" 400, so `_write_actionable_observables` correctly never ran, and
`case_action.actionable_observables_written` correctly came back empty rather than
fabricating IDs for a write that didn't happen. Since all 3 real alerts in this deployment
are permanently already-imported, that path can never show a *successful* write. (2) So the
create+dedup mechanism itself was verified directly and unambiguously against the real,
disposable TheHive test case `~8609848` (already used for real observable-write testing
earlier in this project), bypassing the merge-blocked alerts entirely — real, no mocking:
a value already on the case (`soc3s-test-observable.fake`, id `~4632816`) was correctly
**reused**, not duplicated; a brand-new value (`soc3s-verify-<timestamp>.example`) was
correctly **created**, got back a real new id (`~237816`) TheHive assigned, tagged
`confidence:high`/`disposition:block`, and an independent read-back confirmed it's
genuinely stored. Captured to
`tests/fixtures/case_action_write_actionable_live_run_real.json`.

Test rewrite: `tests/test_observable_writes.py` narrowed to what still exists
(`create_case_observable`'s new ID-returning contract, regression-guarded against the real
captured response shape) — the old `add_extracted_observables`/bucket-tag tests are gone,
their subject retired. New `tests/test_case_action.py::TestWriteActionableObservables` (8
tests: create+id-capture, dedup-reuse, create-failure-still-returns-the-item,
fetch-failure-doesn't-block-create, tag/ioc-reflects-disposition-and-confidence, and the
process/file-share-a-dataType trap re-verified against the new observable_type-keyed
mapping) plus `TestCaseActionWritesObservables` rewired to `verdict.actionable_observables`
instead of `context.extracted_observables`. Mutation-tested: reverting the dedup condition
to `if False` flipped exactly the reuse test red, nothing else. `python3 -m pytest tests/ -q`
— 584 passed (up from 569).

### Fixed — n8n was sending the whole webhook envelope as `raw_alert`, plus a second `max_tokens` calibration gap, 2026-08-23

**Two real, user-discovered issues while testing the deployed service against real n8n
traffic, both live-diagnosed and fixed same day.**

**1. n8n body bug (not this codebase — a workflow config fix).** The user's HTTP node body
was `"raw_alert": {{ JSON.stringify($('Webhook').first().json) }}` — `$('Webhook').first()
.json` in n8n is the *entire* webhook envelope (`{headers, params, query, body, webhookUrl,
executionMode}`), not the actual Security Onion alert, which lives one level down at
`.body`. Diagnosed with certainty from the pattern in a real response: everything sourced
from `hive_alert` (fetched independently by `thehive_alert_id`, e.g. `observables`,
`cortex_results`) kept working; everything sourced from `raw_alert` itself (`rule.name`,
`event_data.*`, `event_dataset`) went to `"unknown"`/`null` — exactly what happens when
`alert_builder.py` looks for `raw_alert["rule"]`/`raw_alert["event_data"]` and finds nothing,
because they're actually nested one level deeper. Fix (n8n-side, not this repo):
`{{ JSON.stringify($('Webhook').first().json.body) }}`. Live-confirmed fixed — the user's
retest immediately after showed `source_engine: "sigma"` and `event_dataset:
"endpoint.events.process"` resolving correctly for the first time.

**2. `max_tokens` calibration gap, round 2 — the first fix's 3.5 chars/token estimate still
underestimated.** Once the `.body` fix above landed, `canonical_alert` started carrying its
*real* content for the first time — entity_id GUIDs, hashes, host/user identifiers, all text
that tokenizes far less efficiently than the mostly-empty/null fields the first `max_tokens`
fix (see above) was calibrated against. Live-caught immediately: a real 19,592-char prompt
measured at **5,799 real tokens** (the backend's own 400 error body) — a 3.38 chars/token
ratio, denser than the 3.5 the first fix assumed. `5799 + 2394 (old capped value) = 8193`,
one token over 8192, so the request was rejected outright with a fast `400` (~450ms — too
fast to be generation, confirming it's a pre-generation validation reject, not a timeout).
Fix: `config.LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN` 3.5 → **3.2**, `LLM_CONTEXT_SAFETY_MARGIN_
TOKENS` 200 → **400** — conservative against both real measurements taken this session (3.38
and the original ~3.7–3.8), with a wider margin since a single point estimate from a handful
of real samples shouldn't be trusted to single-digit-token precision. Live-reverified against
the *exact* real failing prompt: capped `max_tokens` dropped from 2394 to 1669, and the
request was accepted (no more 400) — generation then hit the separate, already-documented
Cloudflare quick-tunnel ~100s `524` timeout instead (this alert's real evidence is richer —
5 MITRE candidates, 2 incident matches — so Stage 3 consistently takes >100s for it now, a
real, current limitation of the temporary tunnel this deployment depends on, not fixable
from this codebase).

New test: `tests/test_context.py::TestCappedMaxTokens::test_reproduces_the_second_live_caught_calibration_gap`,
using the exact real numbers (19592 chars / 5799 real tokens). Mutation-tested: reverting to
the old 3.5/200 defaults reproduces the exact real `5799 + 2394 = 8193` overflow the test
catches; restored. `python3 -m pytest tests/ -q` — 585 passed (up from 584).

**Not built**: `POST /feedback` (Stage 6 audit/FP-feedback — that stage doesn't exist
yet, out of scope per the approved plan). `GET /health`'s minimal scope (LLM-only) was a
deliberate choice, flagged as such — a fuller dependency check is a natural follow-up if
wanted, not a gap in this pass.

### Runbook retrieval (Stage 3→4) + full evidence/reasoning in `/triage`'s response, 2026-08-23

**User-directed, two related asks after seeing real production output.** (1) Query Qdrant
for related runbooks between Stage 3 and Stage 4 so the LLM can use them to inform
`recommended_action`. (2) The final response must surface everything collected/analyzed
across all stages, not just Stage 4's curated summary — full transparency for the
analyst.

**Part 1 — runbook retrieval.** `tools/qdrant.py::retrieve_playbooks` already existed,
fully built and live-verified against the real `soc_playbooks` collection back on
2026-08-16, just never called anywhere (`nodes/rag.py`'s own docstring: its natural query
input is Stage 3's *refined* MITRE mapping, which Stage 2 doesn't have — Stage 3 is now
built). `nodes/analyze.py::_build_playbook_query` (rule title + each refined technique's
id/name/tactic, mirroring `nodes/rag.py::_build_mitre_query`'s style) feeds it, called
directly before `_call_llm` (unwrapped, same reasoning as the case-observables fetch:
`retrieve_playbooks` already self-times-out via new `config.STAGE_4_TOOL_TIMEOUT_QDRANT`
and never raises). Results land on `TriageVerdict.runbook_matches` post-hoc (same place
`stage_4_duration_ms` is already set), independent of whether the LLM call itself
succeeded — attached even on the deterministic fallback path. `prompts/analyst_agent.py`'s
`SYSTEM_PROMPT` instructs the model to treat `runbook_matches` as reference procedural
guidance, not evidence about the specific alert.

**Part 2 — output completeness.** `TriageResult` gained two kinds of new fields:
flat convenience fields (`stage_3_reasoning`, `contextual_modifiers`, `refined_mitre_mapping`,
`investigation_gaps`, `extracted_observables`, `threat_intel`, `runbook_matches`) for
quick-glance access, AND the complete underlying objects (`gathered_evidence:
EnrichedEvidence`, `stage_3_assessment: ContextualAssessment`) for full audit-trail
drill-down — deliberately redundant (the flat fields are all reachable through the two
full objects too), chosen over removing the flat fields since analysts benefit from both a
quick summary and complete detail, and nothing about this is a correctness risk, only
payload size. All of this was already in scope at `nodes/score.py::priority_scoring`'s
existing `TriageResult(...)` construction site — it already receives the full `context`/
`evidence` objects these are copied from, so this required zero new stage-boundary wiring,
purely additive schema fields.

**Live-verified three ways** (`.env`'s Colab/vLLM tunnel rotated twice more during this
work — same recurring pattern this session has documented repeatedly; expect this every
session against this temporary backend):
1. `tools.qdrant.retrieve_playbooks` called directly against the real `soc_playbooks`
   collection: 3 real hits (Privilege Escalation / Unauthorized Access / Data Exfiltration
   runbooks), real scores ~0.55, no `Gap`.
2. A real `POST /triage` through the persistent service (`~4636880`, real backends):
   Stage 3 fell back (see finding below) but the new runbook-retrieval code still ran
   correctly against the fallback's minimal MITRE mapping, returned a legitimate
   zero-hit, `Gap`-free result (no exception, no false warning) — proves the "never
   blocks" contract holds even when Stage 3 degrades.
3. A diagnostic run (reduced `max_tokens` for Stage 3 only, to work around finding #1
   below) got Stage 3 real output for this alert, but then hit finding #2 below
   (Cloudflare's tunnel timeout) before Stage 4 could complete — the runbook feature's
   correctness was confirmed via (1) and (2) above; a single run showing BOTH a real
   non-fallback Stage 3 AND a populated `runbook_matches` in the same request was not
   achieved this session, blocked by the temporary tunnel's real constraints below, not
   by anything in this feature's own code.

23 new tests: `tests/test_analyze.py::TestRunbookRetrieval` (5, including a Gap not
blocking a valid verdict, and `runbook_matches` surviving onto the fallback path),
`tests/test_scoring.py::TestPriorityScoringNode::test_stage_3_and_threat_intel_and_runbook_fields_copied_through`
(1, mutation-tested — reverting `stage_3_reasoning`'s copy confirmed the test goes red),
plus signature-only updates to 4 existing tests. `python3 -m pytest tests/ -q` — 575
passed (up from 569); the pre-existing `test_fp_tracking.py` timing flake reproduced once
under load, clean on rerun, unrelated (documented recurring behavior).

**Two real findings from this session's live verification, unrelated to this feature's
own code — flagging per CLAUDE.md's own standing instruction to surface rather than
silently work around:**

1. **Stage 3's fixed `max_tokens=4000` can overflow the 8192 context window on a richer
   alert.** Live-reproduced on `~4636880` once Stage 2 returned 5 MITRE candidates + 2
   incident matches (vs. 0 on this session's earlier, smaller test runs): real prompt was
   4193 input tokens; `4193 + 4000 (max_tokens) = 8193 > 8192`, and vLLM correctly
   rejected it with a real `400`: `"This model's maximum context length is 8192
   tokens... your prompt contains at least 4193 input tokens"`. Stage 3's own fallback
   handled it gracefully (no crash, `confidence=low`, MITRE mapping preserved from
   `rule_context`), but this is a real quality-degrading bug: any sufficiently
   evidence-rich alert silently loses Stage 3's LLM refinement entirely. Not fixed this
   pass — flagging for a follow-up (options: measure the built prompt and cap
   `max_tokens` to the real remaining headroom, or truncate the RAG-match lists fed into
   the prompt more aggressively for large `mitre_candidates`/`incident_matches` counts).
2. **The Cloudflare quick-tunnel this session's `.env` points at enforces a hard ~100s
   proxy timeout (`524 A timeout occurred`), independent of `.env`'s
   `STAGE_3_LLM_TIMEOUT=600`/`STAGE_4_LLM_TIMEOUT=600`.** Live-reproduced: a Stage 3 call
   that took >100s to generate got killed by Cloudflare's own proxy layer with a 524 HTML
   error page (not a JSON error — `resp.json()` would itself fail on this), well before
   `httpx`'s 600s client-side timeout ever had a chance to fire. This session's earlier
   successful Stage 3 calls (76–86s) happened to land under this ceiling by chance,
   not because the configured timeout was actually honored end-to-end. **This is a hard
   ceiling on this temporary backend that no `.env` value can raise** — a permanent
   (non-quick-tunnel) deployment of the Colab/vLLM endpoint, or moving back to a
   directly-reachable host (like the original Ollama deployment), would remove it
   entirely. Worth knowing before relying on `STAGE_3_LLM_TIMEOUT`/`STAGE_4_LLM_TIMEOUT`'s
   generous values against this specific tunnel.

### Fixed — `max_tokens` context-window overflow, 2026-08-23

**User-directed fix, same day as the finding above.** `nodes/context.py`/`nodes/analyze.py`
both gained `_capped_max_tokens(system_prompt, user_prompt, desired)` — caps the requested
completion `max_tokens` so `estimated_prompt_tokens + max_tokens + safety_margin` stays
under the model's real context window, instead of always requesting the fixed
4000/2000. No local tokenizer exists for this model (a non-OpenAI BPE vocab), so prompt
size is estimated from character count via new `config.LLM_TOKEN_ESTIMATE_CHARS_PER_TOKEN`
(default 3.5, deliberately conservative — this session's real vLLM `usage` data measured
~3.7–3.8 chars/token, and a lower divisor overestimates tokens, the safe direction to be
wrong in) against new `config.LLM_MAX_CONTEXT_TOKENS` (default 8192, this deployment's
real `max_model_len`) and `config.LLM_CONTEXT_SAFETY_MARGIN_TOKENS` (default 200). Floors
at new `config.LLM_MIN_COMPLETION_TOKENS` (default 500) rather than going to zero/negative
on a pathologically large prompt — that case can't be fully solved by this fix (the prompt
alone already exceeds the window), so it attempts anyway with minimal room and lets the
existing fallback machinery catch total failure, same posture as everywhere else in this
codebase. `_capped_max_tokens` is duplicated in both files rather than shared, same
reasoning as `_extract_first_json_object`'s existing precedent.

**Live-verified on the exact alert/scenario that originally exposed the bug** (`~4636880`,
same real backends, tunnel rotated again in between — same recurring pattern): Stage 3's
LLM call log now reads `max_tokens=2754` (capped down from the desired 4000) and
**completed successfully in 101.6s** with real, non-fallback output (`confidence=low
action=merge modifiers=2`, genuine `stage_3_reasoning` text, real `extracted_observables`)
— where the identical alert 400'd outright before this fix. Stage 4's `max_tokens=2000`
was left uncapped this run (its smaller prompt didn't need it), confirming the cap is
conditional, not a blanket reduction.

9 new tests: `tests/test_context.py::TestCappedMaxTokens` (5) and
`tests/test_analyze.py::TestCappedMaxTokens` (4) — small-prompt-unchanged, large-prompt-
capped (with the arithmetic invariant checked directly), the exact live-caught numbers
reproduced (4193 real tokens + desired 4000 would have summed to 8193), the floor on a
pathological prompt, and an end-to-end payload-capture test proving the cap reaches the
real request, not just the standalone helper. Mutation-tested: reverting
`_capped_max_tokens` to `return desired` flipped exactly the 4 tests that exercise capping
behavior red (the small-prompt test correctly stayed green), restored. `python3 -m pytest
tests/ -q` — 584 passed (up from 575).

### Desired max_tokens made per-stage configurable, and raised for the Gemini test session, 2026-08-23

`nodes/context.py`/`nodes/analyze.py`'s `_capped_max_tokens(..., desired=...)` calls took a
bare literal (`4000` / `2000`) until now — fine for the primary foundation-sec-reasoning/
Ollama/vLLM deployment this repo was built against, a real blocker once `LLM_BASE_URL` was
pointed at Gemini for testing (see the backend-swap entry above). New `config.py` constants
`STAGE_3_DESIRED_MAX_TOKENS` / `STAGE_4_DESIRED_MAX_TOKENS` (defaults 4000/2000, matching the
old literals exactly — no behavior change for the primary deployment) now feed those calls;
raising them is a `.env`-only override for this Gemini session, so the original deployment's
calibration is undisturbed on revert.

**Why this needed live data, not a guess**: `GET /v1beta/models/gemini-3.6-flash` (real,
live) confirmed `inputTokenLimit=1048576`, `outputTokenLimit=65536`, `"thinking": true` —
this model spends a variable, invisible slice of the SAME `max_tokens` budget on internal
reasoning before any visible output, not reflected in `completion_tokens` (see the escaping-
bug entry above for the first live repro of this). `.env` now sets `LLM_MAX_CONTEXT_TOKENS=
1048576` (the real confirmed input limit — makes the prompt-vs-budget cap a no-op for this
pipeline's actual prompt sizes, a few thousand tokens) and `STAGE_3_DESIRED_MAX_TOKENS=8000`.

**`STAGE_4_DESIRED_MAX_TOKENS` needed two raises, both live-caught, not assumed.** First
raise (4000 → 8000, alongside Stage 3): a real `/triage` call against the real merge-scenario
alert (`~4636880` → case `~4464672`, both already proven reachable this session) hit
`finish_reason="length"` at 4000 — `completion_tokens=1004` but `total_tokens=9202` against a
5221-token prompt, meaning **~2977 tokens went to invisible thinking alone**, on top of a
visible JSON output now much larger than before Stage 4's "judge every observable" rebuild
(TASK 5, above) — this alert's real merge target has 21 real case observables, each needing
its own judged entry. A diagnostic script (`diag_stage4_raw.py`, capturing the raw HTTP
response directly rather than letting `nodes/analyze.py`'s own defensive parse swallow the
failure into a fallback) confirmed the exact cause before raising anything, per this repo's
"real before mocked" discipline. **Second raise (8000 → 16000)**, live-verified clean:
`finish_reason="stop"`, `completion_tokens=866`, `total_tokens=8973`, 10 real
`actionable_observables` entries (domain/url/hash×2/file/ip×3/process-path×2), each with a
real confidence and disposition — parsed and validated end-to-end, not just inspected as raw
text.

**Re-verified through the real `/triage` HTTP endpoint itself**, not just the diagnostic
script — restarting the running `uvicorn` service was necessary here (a real gotcha caught
live: the first HTTP re-test after editing `.env` still showed `max_tokens=4000` in the log,
because the running process had `.env` loaded at its own import time, before the edit; a
process restart was required to pick up the new value — config hot-reload was never a
feature of this service). After the restart: `POST /triage` on the same real alert completed
in 65.9s, `max_tokens=16000` in the log, `verdict=true_positive`,
`recommended_action=merge_and_retier`, no fallback on either stage. The response's own
`actionable_observables` came back empty in this specific run — expected, not a bug: this
alert was already merged into its target case during an earlier session's endpoint-discovery
work, so `merge_alert_into_case` correctly 400s ("Alert is already imported") and
`case_action.py`'s observable-write (gated behind create/merge succeeding, by design) never
runs. The diagnostic script's direct capture above already proved Stage 4's own judgment
produces the full 10-item list when not blocked by that pre-existing, unrelated state.

Two new tests (`TestCappedMaxTokens::test_call_llm_uses_configured_desired_value_not_a_
hardcoded_literal` in both `tests/test_context.py` and `tests/test_analyze.py`) monkeypatch
the new config constants and confirm an uncapped small-prompt call's payload reflects
whatever config says, not a baked-in literal. Mutation-tested: reverting both `nodes/
context.py`/`nodes/analyze.py` back to the hardcoded `4000`/`2000` literals flipped exactly
those 2 new tests red (and nothing else), restored. **The pre-existing `LLM_MAX_CONTEXT_
TOKENS`-dependent tests needed a matching fix**: `.env`'s now-huge `LLM_MAX_CONTEXT_TOKENS`
override bled into the test suite (config.py loads `.env` at import time regardless of who's
running it), silently turning several capping-behavior tests into no-ops since a 5000-6500
token synthetic prompt no longer approaches a ~1M-token window. Fixed by pinning
`LLM_MAX_CONTEXT_TOKENS` back to 8192 via `monkeypatch` inside each of those tests — they
test the capping *mechanism*, not which backend happens to be configured in `.env` right now.
`python3 -m pytest tests/ -q` — 587 passed (up from 584).

### Fixed — observable description now states the recommendation, and a race with TheHive's own alert-import fixed, 2026-08-23

**Two user-directed fixes from a real live `/triage` run reviewed together.**

**1. Observable description.** `nodes/case_action.py::_write_actionable_observables`'s
`message` sent to `create_case_observable` was `item.reasoning` alone. Now
`f"Recommendation: {item.recommended_disposition}. {item.reasoning}"` — an analyst reading
the observable in TheHive sees the recommended action without cross-referencing tags.
Confidence stays a tag (`confidence:<value>`, unchanged), as does `disposition:<value>` —
neither was asked to move, only the description was asked to gain content. Live-verified
against the real disposable test case `~8609848`: created observable `~299256`, read back
directly via TheHive's own query API, `message` field confirmed exactly
`"Recommendation: block. Test reasoning text for description live-verify."`.

**2. Race with TheHive's own alert-to-case observable import.** Live-caught reviewing a real
`/triage` run (alert `~131208`, new case `~291008`): only 2 of 6 `actionable_observables`
were written; 4 failed with TheHive's own `"Observable already exists"` error. Root cause,
confirmed by querying the real case directly: `create_case_from_alert` (the "new case" path)
triggers TheHive's own background import of the alert's observables into the just-created
case — visible as TheHive's own `re&ct:*`/`field:*` tags on those rows, a process not
guaranteed complete by the time `_write_actionable_observables`'s existence pre-check runs a
moment later. The pre-check missed 4 items that genuinely already existed (the malicious
hash, its imphash, the download URL, the `github.com` domain); TheHive's own uniqueness
constraint caught all 4 collisions at create time and rejected them, and the code discarded
the real IDs entirely, marking them `failed`. Worse:
the same run also produced a genuine **duplicate** — `172.20.24.99` (an `ip` observable)
was NOT rejected by TheHive's own constraint and now exists twice on that case, once
auto-imported (no tags) and once soc3s-created (with our tags) — a different failure mode
(no error to catch) this fix does not address.

**Fix**: on a create failure whose `Gap.reason` matches TheHive's own `"already exists"`
error text (new `_is_already_exists_conflict`), re-fetch the case's observables once (lazily,
shared across all conflicts in the same call — not one re-fetch per conflicting item) and
reuse the real existing ID instead of discarding it. Scope is deliberately narrow: this
recovers the ID so the value is correctly represented in `TriageResult.actionable_observables`
— it does NOT retroactively apply Stage 4's tags/message onto the pre-existing,
TheHive-auto-imported row, since no update-observable endpoint exists in this codebase yet.

**Live-verified against the real backend**, not just mocked: reproduced the exact race
directly against the real disposable test case `~8609848` — a value
(`soc3s-test-observable.fake`) that genuinely already exists on that case, with only the
FIRST `fetch_case_observables_with_type` call monkeypatched to return empty (simulating the
race window), everything else (the real create call's real rejection, the real recovery
re-fetch) hitting the live backend for real. Result: `written=1, failed=0`, recovered the
correct real ID (`~4632816`, matching the case's actual stored observable — confirmed against
a direct query beforehand), exactly 2 fetch calls (pre-check + one conflict re-fetch, not one
per conflict).

3 new tests in `tests/test_case_action.py`: the recovery path itself (mocked fetch/create,
asserting exactly 2 fetch calls), a conflict whose re-fetch genuinely doesn't contain the
value (must still report failed, not silently swallowed), and a non-conflict failure (a
timeout) confirmed to NOT pay the extra re-fetch cost. Mutation-tested: replacing the
conflict-detection branch with `if False` flipped exactly the recovery test red (the other
two correctly stayed green — they exercise paths the mutation doesn't touch), restored.
`python3 -m pytest tests/ -q` — 591 passed (up from 587).

**Not addressed by this pass**: the duplicate-`ip`-observable failure mode (no error to catch,
so this fix's detection can't fire), and the one real duplicate it already produced on case
`~291008` (`172.20.24.99` exists there twice) — flagged to the user, not cleaned up
unprompted since deleting TheHive data needs explicit confirmation.

---

## Deferred requirements — RESOLVED 2026-08-21 (Stage 5 build)

Both of this table's former entries are now built in `scoring.py` exactly as
specified here: `rule_status_penalty` (`scoring_config.RULE_STATUS_PENALTY`,
wired via `scoring._rule_status_penalty`) and `llm_criticality_score` as the
fourth weighted, augmenting component (`compute_final_priority`'s
`weight_sum` division). See "Stage 5 — hybrid priority scoring built" below
for the live-verified build. Table removed; both are load-bearing code now,
not a future step.

---

## Ground truth hierarchy

When two sources disagree about what a field is called or what it contains, the
higher tier wins. Every non-obvious field mapping in this repo should be
traceable to tier 1 or 2.

| Tier | Source | What it proves | What it does NOT prove |
|---|---|---|---|
| **1** | A live call to the real backend, made during development | This is what the system actually returns, today | That it is returned for every alert shape |
| **2** | A real captured alert or document (`tests/fixtures/sigma-alert-real.json`, `so_detection_5e3cc4d8.json`) | This shape exists in production | That other shapes look anything like it |
| **3** | `ingest-templates.txt` — live index field mapping | A field *name and type* exists in the index | That any document populates it; it carries **no values**, so it can never tell you which `event.dataset` a shape belongs to |
| **4** | `so-alert-reference/` — Security Onion's own pipelines and templates | A field *can* be produced, and what SO calls it | That this deployment produces it |
| **5** | `SOC-3s-ARCHITECTURE-v4.md` / `SOC-3s-IMPLEMENTATION-GUIDE.md` | Design intent, and why | Specific field names or response shapes — both docs have been wrong on specifics, see below |
| **6** | Inference from general SOC/ECS knowledge | Nothing | Anything. Never sufficient on its own. |

**The docs have been wrong on specifics twice, both caught by tier 1:**

- Implementation guide §0.2 calls `so-ioc-normalize` a Security Onion pipeline.
  It is a custom one. §0.2's *conclusion* still binds; its attribution does not.
- Architecture §6 tool 2's example `RuleContext` differs from the real
  `so-detection` document in four ways (index wildcard, `language` vs `engine`,
  MITRE living only in the `content` YAML, `falsepositives: ["Unknown"]`).

Treat both documents as authoritative on *intent and constraints*, and as
unverified on *field names and response shapes* until a tier-1 call confirms them.

## Fixture discipline

From implementation guide §0.1, §2 and §6. The gap between "tests pass" and
"works against the real backend" is the specific failure this project has
already been burned by — §6 calls green-mocks and a working pipeline *different
claims*.

**1. Real before mocked, always.** A tool is not done when it type-checks or
passes a mocked test. It is done when it has been called against the real live
backend at least once and the actual response inspected field-by-field against
its Pydantic model. Mocked tests are written *after* that, **from the captured
real response saved as a fixture** — never from an imagined shape, never instead
of the real call. Full loop in §2: signature → minimal real call → run it → compare
→ *then* error handling → *then* mocked tests → *then* wire into `gather.py`.

**2. Every fixture declares provenance and scope.** In its docstring or an
adjacent comment:

- Real → name the exact source and the shape it covers:
  `# REAL — endpoint.events.process, verbatim from .ds-logs-detections.alerts-so-2026.08.02-000147, pulled 2026-08-08.`
- Synthetic → say so unmissably, and say what it was built from:
  `# SYNTHETIC — field paths from ingest-templates.txt mapping union. No real alert of this dataset shape exists to validate against yet.`
- Suricata / YARA → the §0.1 wording verbatim:
  `# NOTE: Suricata path — unit-tested against synthetic fixture only, no live SO alert exists yet to validate against.`

**3. One real fixture proves one shape.** `sigma-alert-real.json` covers
`endpoint.events.process` — 93% of this deployment's volume — and nothing else.
Passing tests against it says nothing about `endpoint.events.file`,
`.library`, `.api`, `windows.sysmon_operational`, `kratos.audit` or
`system.auth`. Never report shape coverage that only synthetic fixtures back.

**4. Don't sanitise a real fixture.** `sigma-alert-real.json` keeps its `ioc.*`
block precisely because production has it — that is what lets the guard test
prove the code ignores it on *real* data. A cleaned-up fixture tests a world
that does not exist.

**5. Verify tests aren't vacuous.** After writing a fixture-backed suite, break
the mapping deliberately and confirm the suite goes red. A test asserting
against a field the code never populates passes for the wrong reason.

**6. Sigma-only integration coverage is the expected state**, not an incomplete
build (§0.1). Build the Suricata and YARA paths per spec, unit-test them against
synthetic fixtures, mark them unverified, and do not let that block calling a
step done.

## Reference material in this repo

- `so-alert-reference/` — **build-time only**, never imported at runtime. Security Onion's
  own ingest pipelines, ECS/SO component templates, and the Sigma alerter source. Consult it
  to answer "what does Security Onion actually call this field" instead of guessing.
  `so-alert-reference/templates/so/detection-mappings.json` is the schema of the
  `so-detection` index that `detection_rule_lookup` queries.
- `ingest-templates.txt` — **build-time only.** Despite the filename, this is a live
  `logs-detections.alerts-so/_mapping` dump covering 24 backing indices
  (2026.06.21 → 2026.07.16). It carries field *names and types*, not field *values* — no
  `event.dataset` value strings appear in it. Use it as ground truth for field paths when
  building synthetic fixtures for dataset shapes with no real captured alert.
- `sigma-alert-sample.json` — one real captured alert, in the n8n webhook envelope shape
  (`payload[0]["body"]` is the `raw_alert`). It covers the **`endpoint.events.process`**
  dataset shape and **only** that one. Passing tests against it proves that one shape works;
  it proves nothing about the others.

## Fixture labelling discipline

Every test fixture must state which dataset shape it covers and whether it is real or
synthetic:

- Real captured alert → name the dataset explicitly, e.g.
  `# REAL — endpoint.events.process, from sigma-alert-sample.json (xordump/Invoke-WebRequest).`
- Synthetic → mark it unambiguously, e.g.
  `# SYNTHETIC — field paths from ingest-templates.txt mapping union. No real alert of this`
  `# dataset shape exists to validate against yet.`
- Suricata / YARA paths → per Implementation Guide §0.1:
  `# NOTE: Suricata path — unit-tested against synthetic fixture only, no live SO alert exists yet to validate against.`

Never let a green test suite built on synthetic fixtures be reported as evidence that
extraction works in production.

## Scope discipline

On multi-part work: never skip, silently simplify, or drop part of a task because it is
large or tedious. If it is too big for one pass, break it into explicit sub-steps, say so,
and do all of them in sequence. If a part genuinely isn't worth doing, say so and ask
before dropping it.
