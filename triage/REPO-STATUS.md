# SOC-3s — Repository and Deployment Status

Living document. Records **verified facts about this specific deployment** —
things confirmed by a real backend call, with the date and the evidence — plus
where the build has got to.

`CLAUDE.md` holds operating rules. This file holds observed reality. When they
disagree, something has changed in the environment and both need revisiting.

---

## Deployment facts

Every entry here was verified against a live backend. None is inferred.

### The `so-ioc-normalize` pipeline is LIVE and stamps `ioc.*` on most alerts

**Verified 2026-08-08** by date histogram over `logs-detections.alerts-so*`.

| Period | Alerts | With `ioc.*` |
|---|---|---|
| 2026-07-13 → 07-15 | 2,148 | 0 |
| 2026-07-16 → 08-07 | 5,571 | 5,571 (100%) |
| **Total in index** | **7,719** | **5,571 (~72%)** |

The pipeline went live on **2026-07-16** and is still running — alerts from
2026-08-07 carry it. The ~72% figure is purely an artifact of the index also
holding three days of pre-deployment history; **every alert produced from
2026-07-16 onward has `ioc.*`, and every future alert will**, unless the
pipeline is removed.

**Why this matters for later stages:**

- `ioc.*` is **not** a Security Onion field. It is written by a custom pipeline
  (`so-alert-reference/ingest/so-ioc-normalize`) whose own description places it
  *after* "Security Onion's own" chain. Nothing in this repo may read it.
- It sets `ioc.source_engine = ctx.event.module`, so it is **derived from**
  `event.module` and can never independently corroborate it. Engine detection
  reads `event.module`, falling back to the `event.dataset` prefix.
- The rule is **"present but never read"**, not "absent". Finding `ioc.*` in a
  real alert is not evidence it is safe to use. Real fixtures deliberately keep
  it (`tests/fixtures/sigma-alert-real.json`) so the guard test proves the code
  ignores it on production data.
- `ioc.indicators` in particular is a trap for **Stage 1 and Stage 2**: it looks
  like a ready-made IOC list. Implementation guide §0.2 is binding — IOCs come
  from `hive_alert.observables`, extracted upstream in n8n. The pipeline only
  ever builds `indicators` from a network 5-tuple, DNS, URL or file hash, none
  of which exist on a Sigma process alert, so it is structurally always empty
  for 100% of what currently fires here.
- **`ingest-templates.txt` shows an `ioc` mapping in only 1 of 24 backing
  indices.** That dump ends on 2026-07-16 — the day the pipeline went live — so
  that count measures *recency, not rarity*. Do not repeat this misreading.

Regression guards: `test_ioc_field_is_ignored_entirely` (synthetic, contradictory
values) and `test_ioc_present_in_real_production_data_and_still_ignored` (real
production document).

### iTop CMDB is 1 real asset and 31 demo objects — impact scoring is a constant today

**Verified 2026-08-08.** REST v1.3 at `http://172.20.24.223/itop`, credentials
valid. Implementation guide §3's stop-and-report gate was run and reported.

The asset resolves: `PC::32` / `win-kvkmd51ggkq`, `business_criticity = "medium"`.
So this does **not** hit §3's literal stop condition (`found: false` or
`criticality: null`). But three things make it the same situation in practice:

| Field (architecture §6 tool 5) | Reality in this iTop |
|---|---|
| `criticality` | `business_criticity = "medium"` — populated, but medium is the formula's own baseline, so it discriminates nothing |
| `network_zone` | **Attribute does not exist on any class.** IP Management extension absent (`IPv4Subnet` is not a valid class) |
| `data_sensitivity` | **Attribute does not exist on any class** |
| `owner` | **No attribute.** `contacts_list` empty; zero contact links in the entire CMDB |
| `services` | `services_list` empty |
| IP lookup | **Impossible.** `PhysicalInterface` and `NetworkInterface` both return 0 rows; no object carries an IP |

Contents: 32 CIs, of which **31 are iTop's stock demo fixtures** (Apache, CRM,
ERP, ESX1-3, Server1-4, VM1-4, Rack1, Router1, Switch1, Sugar CRM, …). Only
`win-kvkmd51ggkq` is real.

Observed `business_criticity` enum across all 32: `low` (27), `medium` (2),
`high` (3). OQL does not validate enum values in a WHERE clause, so this is an
observed set rather than a schema-derived one; `tools/itop.py` passes an unseen
value through and logs it rather than coercing it.

**Maintainer decision 2026-08-08:** population is a separate data task, to be
handled when sensors are deployed and real assets exist. The tool is built
correctly now so it works the moment data appears — not skipped or simplified.
`network_zone` / `data_sensitivity` return None with a gap logged. **Subnet maps
must NOT be added to config or scoring to synthesise a zone.** When custom
fields land in iTop the change is purely additive: one extra field read, same
return model, no downstream change.

**Join key:** `asset_number` holds the Elastic Agent host UUID and matched
`event_data.host.id` exactly (`c8fc26bf-dc76-4dba-adbb-bf31640d9c9f`). It is the
primary lookup, hostname the fallback.

Two API behaviours that cost real debugging and are now regression-guarded:

1. `output_fields: "*"` returns only attributes of the **class you query**, not
   the object's subclass. `FunctionalCI` omits `asset_number`; `PhysicalDevice`
   omits `osfamily_name`. Hence a two-phase locate-then-refetch-on-`finalclass`.
2. `asset_number` is **not filterable on `FunctionalCI`** ("Unknown filter
   code") and does not exist on `VirtualMachine` at all — VMs are not
   `PhysicalDevice`, so only the hostname fallback reaches them.

iTop returns **HTTP 200 with a non-zero `code`** for API errors; it does not use
HTTP status codes.

### TheHive moved, was upgraded, and now has cases

**Verified 2026-08-09.** TheHive **5.7.3-1**, now behind a base path:
`http://172.20.24.221:9000/thehive` (Cortex likewise at `:9001/cortex`). New API
key. The instance was largely rebuilt — 3,640 alerts → 4.

| Entity | 2026-08-08 | 2026-08-09 |
|---|---|---|
| Cases | 0 | **2** — `~9212080` Closed/TruePositive, `~4481232` New/New |
| Alerts | 3,640 | 4 |
| Cortex jobs | 5,108 | 48 |

Both case tools were re-run against real cases and are **correct**:
`search_open_cases_by_entities` returned only `~4481232` and excluded the closed
one; `search_closed_cases_by_rule` returned `tp_count=1, avg_severity=3.0` from
`~9212080`. The stage-vs-status distinction is now proven empirically, not just
from schema. `created_at` parsed as 2026, confirming the epoch-millisecond fix
on real data.

Fixtures re-captured as `tests/fixtures/thehive_real.json`; the 5.6.1-era
fixture and its shape-proof counts (99/12) are removed as superseded.

### TheHive moved AGAIN, upgraded to 5.7.5-1, custom Function retired

**Verified 2026-08-13.** `http://172.20.24.228:9000`, base path is `/api/v1`
directly now — **not** `/thehive`. That old prefix now returns HTTP 200 with
the SPA's HTML (a trap: it looks reachable and isn't the API). New API key.

The custom `getAlertWithObservables` Function — the entire threat-intel path's
hard dependency since 2026-08-09 — is **gone**: `404 Function
getAlertWithObservables not found`. But the external-API limitation that
required it is *also* gone: the stock `getAlert -> observables -> page`
projection now returns `reports[analyzer].taxonomies` directly, no
`extraData` needed. Confirmed live against real alert `~4661456` (4
observables, 3 with real Cortex reports — VirusTotal AND
`OpenCTI_v6_SearchExactObservable_2_0`). `tools/thehive.py::get_full_alert_
with_analysis` was rewritten to two concurrent stock queries; the Function
was not re-registered. `thehive-reference/CONTEXT.md` keeps the old
dependency's writeup as history, clearly marked retired.

Cases changed shape too — three exist now: `~8609848` New/New (a manually
created "test" case with **zero** observables of its own), `~4653208`
Closed/**FalsePositive**, `~8613944` Closed/TruePositive. This is the first
real (not synthetic) FalsePositive closed-case data this repo has had. The
open-case entity query now legitimately returns **empty** for this instance's
alerts — proven not-broken by the closed-case query (same shapes) finding
real matches, and by a direct `getCase -> observables` call on the "test" case
confirming it has nothing to match on. `search_closed_cases_by_rule` now
summarises `tp_count=1, fp_count=1, avg_severity=3.0` — an improvement on
2026-08-09's TP-only real coverage.

Fixtures re-captured as `tests/fixtures/thehive_real.json`; superseded content
(the `function_payload` section, the 2026-08-09 alert/case ids) is removed.

### `CortexResult.verdict` fixed to match its own (already-redesigned) schema — and a resulting rule change

**Fixed 2026-08-13.** `schemas/alert.py`'s `CortexResult` had been redesigned
(2026-08-10) to drop the numeric `score` field entirely and turn `verdict`
into a `list[str]` — closing a real hard-constraint violation (`alert_builder`
was computing a number, 90/55/5/0, outside `scoring.py`). But `alert_builder.
py` was never updated to match, so `_build_cortex_results` still constructed
`CortexResult(verdict=<str>, score=<int>)` — a shape the new model rejects.
**8 tests were failing** with `pydantic_core.ValidationError` before this fix.

Fixing the shape also required deciding the verdict rule properly, since the
old rule (parse a detection ratio like `"3/97"`, threshold it, and let that
override the analyzer's own `level`) was itself the kind of scoring judgement
the redesign was meant to push out of `alert_builder`. **Maintainer decision
2026-08-13**: the analyzer's own `level` is taken as reported, verbatim, for
every taxonomy row — no parsing, no election of "the" verdict row, no
overriding. Every adverse-labelled row (`malicious`/`suspicious`) contributes
to `verdict`; `details`/`taxonomies` keep every row (adverse or not) with its
own label attached.

**This is a real, deliberate behavior change**, not just a bugfix: on real
data (alert `~4661456`, 2026-08-13), VirusTotal's own `GetReport`/`Scan` rows
for the xordump URL are labelled `malicious` directly at a `1/92` ratio — low
by count, but the analyzer's own call, and it is now trusted as-is rather than
re-derived from the number. The 2026-08-09-era `github.com` scenario (a
context row happening to be tagged `malicious` alongside the real `info`-level
ratio row) no longer exists in this instance's current real data to test
against directly — it is preserved as a clearly-labelled SYNTHETIC unit test
in `tests/test_alert_builder.py::TestCortexTaxonomyVerdicts`, since under the
new rule it would legitimately produce `verdict == ["malicious"]` too. The
discrimination CLAUDE.md's hard constraint reserves for Stage 5's LLM — not
`alert_builder` — is what's now expected to weigh a context-row "malicious"
against the real ratio, using the full `details` string it's handed.

### Historical note — the 0-case state (2026-08-08)

**TheHive 5.6.1 at `http://172.20.24.221:9000`.**

| Entity | Count |
|---|---|
| Cases | **0** |
| Alerts | 3,640 |
| Observables | 533,373 |
| Cortex jobs | 5,108 (5,038 Success, 70 Failure) |
| Cortex analyzers | 6 — VirusTotal, MISP, MalwareBazaar, Shodan_DNSResolve, Urlscan_io, AbuseIPDB |

`search_open_cases_by_entities` and `search_closed_cases_by_rule` therefore
return empty for every alert, and `correlation_mode` is `"new"` every time. Per
implementation guide §2 that IS the correct real result at this stage, and
architecture §6 tool 4 expects it to stay empty for ~30 days.

**Empty results prove nothing on their own** — a broken query also returns
empty. The identical query shapes were run against the Alert graph, which has
data: `observable -> alert -> dedup -> count` returned **99**, and the tag
filter returned **12**. Both counts are pinned in
`tests/fixtures/thehive_schema_and_empty.json` as the shape proof.

Three schema facts, from `/api/v1/describe/*`:

1. **`stage` and `status` are different vocabularies.**
   `stage = New | InProgress | Closed`;
   `status = New | InProgress | TruePositive | FalsePositive | Duplicated | Indeterminate | Other`.
   "Open" is `stage != "Closed"`. **There is no `Closed` status**, so filtering
   status for openness silently matches everything.
2. **Rule uuid is NOT searchable.** No rule-uuid attribute on Case or Alert, and
   no customFields. `Alert.sourceRef` holds the Security Onion document id.
   Matching is by the `rule:<name>` tag n8n stamps on alerts, plus shared
   observables; `ClosedCasesSummary.matched_by` records which ran.
3. Case severity is `1..4`, TLP `0..4` — not the 0-100 scale used elsewhere. No
   conversion in the tool; `scoring.py` owns that at step 7.

Also: TheHive returns **epoch milliseconds**. Pydantic reads a bare int as
seconds, which would date every case to 1970 and silently break recency
reasoning. Converted explicitly, with a regression test.

### Cortex taxonomies ARE reachable — via a custom TheHive Function ✅ RESOLVED

**Verified 2026-08-09.** The blocker is closed. `cortex_results` went from
structurally-always-0 to correctly populated.

    POST {THEHIVE_URL}/api/v1/function/getAlertWithObservables  {"alertId": "~4168"}

returns the alert + observables + `reports[analyzer].taxonomies` in **one call**.
It works because the Function's `context.query.execute()` runs on TheHive's
*internal* query engine, whose observable serialiser includes `reports`. The
external API's serialiser strips them — which is why every documented route
failed (see the historical note below).

**This is a HARD DEPENDENCY on a custom server-side JS Function**, not stock
TheHive. Its definition is preserved at
`thehive-reference/getAlertWithObservables.json` with re-registration
instructions. If it is lost to an upgrade, `get_full_alert_with_analysis`
returns an actionable `Gap` naming that file, and the pipeline continues without
threat intel rather than failing.

**Cortex-direct was evaluated and rejected** (maintainer decision 2026-08-09).
It works — `{cortex}/api/job/{cortexJobId}/report` returns the same taxonomies
plus `full` — but costs ~10-14 HTTP calls per alert instead of 1, a second
credential, and a 7th backend, to obtain `full`, which architecture §9
explicitly forbids passing to Stage 4 (the `_summarize_evidence` firewall
truncates `details` to 300 chars). `CORTEX_URL`/`CORTEX_API_KEY` remain in
`.env`, unused, as the documented fallback.

**A verdict-aggregation trap found and fixed.** VirusTotal emits several
taxonomy rows per observable, and `level` colours THAT ROW, not the observable:

| observable | context row | verdict row |
|---|---|---|
| `github.com` | `56 resolution(s)` **[malicious]** | `0/91` *[info]* |
| `powershell.exe` sha256 | `6 contacted domain(s)` **[malicious]** | `0/74` *[info]* |

`_summarize_taxonomies` took `max(level)`, scoring **github.com and
Microsoft-signed powershell.exe as malicious/90**. Since nearly any real
observable has some context row tagged malicious, that would have pinned §10's
`threat_intel_adjustment` near its +30 maximum on every alert — worse than no
threat intel, because an always-empty field is visibly a gap while an always-+30
field looks like working evidence.

**The taxonomies are trustworthy; the aggregation was wrong.** The rule is now:
a detection-ratio row (`N/M`) is the verdict, everything else is context; the
`level` fallback applies only when no ratio exists (MISP-style analyzers).
Thresholds: 0 → clean, 1-4 → suspicious, ≥5 → malicious. Real results:

    xordump URL   3/97 -> suspicious    powershell  0/74 -> clean
    xordump URL   1/92 -> suspicious    github.com  0/91 -> clean

Context rows are preserved verbatim in `CortexResult.details`. Duplicate rows
are de-duplicated (the real payload carries `3/97` twice). Regression guard:
`test_github_com_is_never_malicious`.

### Historical note — why the documented Cortex routes fail

**Verified 2026-08-08.** Two findings:

1. `extraData: ["reports"]` (implementation guide §0.2) is **silently dropped**
   by TheHive 5.6.1 — `seen`, `shareCount`, `permissions` and `links` all
   return, `reports` never does. Report bodies live only on Job objects at
   `/api/connector/cortex/job/{jobId}`; the `/api/v1` query API returns jobs
   without them.
2. Every report has keys `['artifacts', 'full', 'success']` and **no
   `summary`** — checked across all five analyzers with successful jobs.
   `alert_builder._build_cortex_results` reads
   `report["summary"]["taxonomies"]`, so `cortex_results` is structurally always
   empty and §10's `threat_intel_adjustment` is permanently 0.

The underlying data is present, just unsummarised (VirusTotal `full` carries
`reputation`, `sandbox_verdicts`, `last_analysis_stats`).

**Maintainer decision 2026-08-08:** n8n will attach the Cortex report bodies to
the `/triage` payload. This service does not fetch them — consistent with
architecture §6, which already says Stage 1 never calls Cortex. The exact shape
n8n produces is still to be confirmed before `get_full_alert_with_analysis` is
written.

Note also: the alerts in TheHive were **not all created by the n8n workflow**,
so absent reports on those alerts is not evidence of a broken pipeline.

### n8n observable extraction is mislabelling dataTypes

**Verified 2026-08-08** on alert `~1190993992`:

| dataType | data |
|---|---|
| `url` | `"powershell.exe" & {[Net.ServicePointManager]::SecurityProtocol = …` — the **whole command line** |
| `domain` | `https://github.com/dafomdev` — a **URL** |
| `hash` | `1c84c863…` (tags `sha256`) — correct |
| `hash` | `bf7a6e7a…` (tags `imphash`) — correct |

`alert_builder`'s `URL_RE` rescues the second (anything starting `https://` is a
URL regardless of label). The first is unrescuable and will land in
`observables.urls` as a command line, then be sent to Cortex as a URL. Upstream
in n8n, outside this repo, but it pollutes the IOC surface.

### Only Sigma alerts exist

**Verified 2026-08-08.** Aggregation over the whole alerts index returns exactly
one value for each field: `event.module = "sigma"`, `event.dataset =
"sigma.alert"`, 7,719 docs, 100%. No Suricata, Strelka or YARA alert has ever
been written. Matches implementation guide §0.1 — network and file-extraction
sensors are not deployed.

Consequence: all non-Sigma code paths are synthetic-fixture tested only and must
be labelled as such. This is the expected state, not an incomplete build.

### `so-detection` must never be wildcarded

**Verified 2026-08-08.**

| Index | Docs |
|---|---|
| `so-detection` | 74,951 (current rules) |
| `so-detectionhistory` | 345,474 (revisions) |

`so-detection*` matches both, so a wildcard query can return a superseded rule
version. `config.ES_DETECTION_INDEX` is pinned to the exact name.

### Elasticsearch requires an explicit `:9200`

**Verified 2026-08-08.** `https://172.20.24.58` → HTTP 302 (Security Onion web
UI on 443). `https://172.20.24.58:9200` → HTTP 200 with the API key. `config.py`
raises at import if the port is missing. Self-signed cert, so TLS verification
is off by default (`ES_VERIFY_TLS`).

### Ollama has two models, and `qwen3.5:4b` is not one of them

**Verified 2026-08-08.** `172.20.24.225:11434` serves
`foundation-sec-reasoning:latest` and `llama3.2:3b`.

Architecture §19 assigns `qwen3.5:4b` to Stage 3. By deployment decision **both
stages run `foundation-sec-reasoning`** — reasoning consistency over latency.
Stage 3 moves from ~30-60s to ~60-90s, pushing p95 end-to-end toward ~200s,
inside the 300s n8n budget but with less margin than the two-model design
assumed. Flag it back rather than silently swapping models. See CLAUDE.md.

### Redis is not deployed

`REDIS_URL` unset. Stage 0 dedup no-ops — architecture §5 requires Redis absence
never to block the pipeline. Accepted cost: duplicate alerts inside the dedup
window get processed more than once.

### Cortex is not configured, by design

This service never calls Cortex (architecture §6, §13). Reports arrive
pre-computed on the TheHive alert via `get_full_alert_with_analysis`, which as
of 2026-08-13 runs two stock TheHive queries rather than `extraData:
["reports"]` (never worked) or a custom Function (retired — see the TheHive
entries above).

### OpenCTI is reachable, and its `.mcp.json` token had a typo

**Verified 2026-08-13.** `http://172.20.24.222:8080`, GraphQL 7.260318.0.
`{ about { version } }` confirms reachability with a corrected token.

The token stored in `.mcp.json` (`lgrn_octi_tkn_kPT3_...`) returns
`AUTH_REQUIRED` on every call — it is missing a leading `f`. The working token
is `flgrn_octi_tkn_kPT3_...`. Both `.mcp.json` and `.env`'s new `OPENCTI_TOKEN`
now carry the corrected value. `CORTEX_API_KEY` in `.env` was separately
re-checked the same day and still 401s against `/api/analyzer` and
`/api/job?range=...` — unused at runtime either way (see above), not
investigated further since it isn't blocking anything live.

Exact-match observable lookup (`stixCyberObservables(filters: ...)`) is
confirmed working, including batching several values into one query — a
4-value batch containing 2 genuine threat-feed indicators (`w8p3k.com`,
`yezi.haoyun.bar`) and 2 non-matches (`github.com`, this deployment's own
alert sha256 hash) returned exactly the 2 real matches. None of this
deployment's own alert observables exist in OpenCTI's data — expected, since
they're a locally-generated test artifact, not a public IOC; this is the
correct "not found" answer, not a broken query.

---

## Known documentation errors

Both caught by live calls. See CLAUDE.md's ground-truth hierarchy — the design
docs are authoritative on *intent*, unverified on *field names and shapes*.

| Doc | Claim | Reality |
|---|---|---|
| Impl. guide §0.2 | Security Onion "does have a `so-ioc-normalize` ingest pipeline" | It is a custom pipeline, not Security Onion's. §0.2's *conclusion* (IOCs come from TheHive) still binds; its attribution does not. |
| Arch. §6 tool 2 | Example `RuleContext` shape | Differs in four ways: index must not be wildcarded; `source_engine` comes from `language` not `engine`; MITRE lives only in the `content` YAML (doc-level `tags` is null); `falsepositives` is commonly the literal `["Unknown"]`. |
| Arch. §7 | Example `mitre_techniques`/`soc_playbooks`/`cve_context` payloads | All three differ from the real ingested points — see "`tools/qdrant.py` built" below for the full field-by-field diff. `MitreCandidate`/`PlaybookMatch`/`CveMatch` were corrected to match live data. |

---

## Build progress

Build order is architecture §18.

| Step | Scope | State |
|---|---|---|
| 1 | `schemas/alert.py`, `alert_builder.py`, tests | **Done** — 54 tests |
| 2 | `schemas/evidence.py` + six Stage-1 tools | **Done** |
| 2a | `schemas/evidence.py` | Done |
| 2b | `tools/detection_rules.py` | **Done — live-verified** against rule `5e3cc4d8-…`, 38 tests |
| 2c | `tools/itop.py` | **Done — live-verified** against `PC::32`, §3 gate run and reported, 30 tests |
| 2d | `tools/fp_tracking.py` | **Done — live** (local SQLite, `config.FP_TRACKING_DB_PATH`, no external backend to verify against), tests |
| 2e | `tools/thehive.py` | **Done — live-verified against real cases, re-verified 2026-08-13** after TheHive moved to 172.20.24.228 (5.7.5-1) and its custom Function was retired. All three functions: `get_full_alert_with_analysis` (rewritten to two stock queries), `search_open_cases_by_entities`, `search_closed_cases_by_rule`. 37 tests |
| 2f | `tools/elasticsearch.py` | **Done — live-verified**, tests |
| 2g | `tools/opencti.py` | **Done — live-verified**, 2026-08-13. Deployment-added Stage-1 tool, not in architecture v4's original 7 — see CLAUDE.md "OpenCTI". 11 tests |
| 3 | `nodes/gather.py` — Stage 1 parallel evidence gather | **Done.** All 8 tool calls (7 architecture §6 names + `opencti_observable_enrichment`) wired through one `asyncio.gather(..., return_exceptions=True)`, double-guarded per-tool. Tests. |
| 4 | `tools/qdrant.py` + three ingest scripts + `nodes/rag.py` — Stage 2 | **In progress.** `tools/qdrant.py` and `nodes/rag.py` both done — see "tools/qdrant.py built" and "nodes/rag.py built — playbooks moved out of Stage 2" below. Three ingest scripts (MITRE/playbook/CVE Qdrant population) not started — this deployment's four Qdrant collections were populated by some other process before this repo's build reached them; no ingest script exists in this repo yet, verified/populated data is simply assumed live. |
| 5 | `schemas/assessment.py`, `prompts/context_agent.py`, `nodes/context.py` — Stage 3 | **Done — live-verified**, 2026-08-16. See "`nodes/context.py` built" below. |
| 6-12 | Stages 4-6, pipeline, main | Not started |

Supporting files built outside the numbered steps: `config.py` (required by every
tool; `python config.py` is architecture §16's config-validation item) and
`tools/es_client.py` (shared ES transport, not a tool — no query logic).

**Current test count: 305, all passing.** Every fixture-backed suite has been
mutation-checked — the mapping was deliberately broken and the suite confirmed to
go red — so a green run is not a vacuous one.

### `nodes/context.py` built — Stage 3, first of the pipeline's 2 LLM calls

**2026-08-16.** `schemas/assessment.py` (`ContextualAssessment`, `MitreMapping`,
`CorrelationDecision`, `ContextualModifier` — architecture §18's exact four names),
`prompts/context_agent.py` (system/user prompt + output schema), and `nodes/context.py`
(orchestration + deterministic fallback) are built and live-verified end-to-end. Two
real, load-bearing findings surfaced during the required real-before-mocked build
step (Implementation Guide §5) — both now documented in CLAUDE.md's
deployment-decisions section, not just here:

1. **Ollama's `response_format: json_schema` mode hangs on Pydantic's default
   `$defs`/`$ref` schema output.** Sent as `ContextualAssessment.model_json_schema()`
   produces it: the call did not return after 280+ seconds, killed by hand. The
   identical schema hand-inlined (no `$defs`): 68.9s, clean output. `prompts/
   context_agent.py::CONTEXTUAL_ASSESSMENT_SCHEMA` is therefore hand-written, checked
   against drift by `tests/test_context.py::TestSchemaStaysInSync`. This will need
   redoing for Stage 4's `TriageVerdict` schema too.
2. **Plain `json_object` mode isn't safe** — the model emits one valid JSON object
   then hallucinates extra Q&A turns with more JSON/prose appended after it.
   `_extract_first_json_object` uses `json.JSONDecoder().raw_decode()`, not
   `json.loads()`, and stays defensive even under `json_schema` mode.

**Real end-to-end timing**: a full live Stage 3 call (real `EnrichedEvidence` for the
xordump alert, built through the real Stage 1→2 chain, real
`foundation-sec-reasoning:latest` call) took **271.1 seconds** — well past architecture's
120s default and past this deployment's own prior "~60-90s" estimate (CLAUDE.md). `.env`'s
`STAGE_3_LLM_TIMEOUT` is now `600` for this CPU-bound host; `nodes/context.py`'s call logic
has no CPU/GPU branching, only the config value changed. The deterministic fallback path was
also deliberately triggered live (unreachable `LLM_BASE_URL`) — 0.14s, valid
`ContextualAssessment`, `confidence="low"`, the real rule's MITRE technique (`T1105`)
preserved from `rule_context.mitre_attack`, matching architecture §8's explicit
anti-regression requirement (the v3 silent-severity-cap bug: fallback must never emit an
empty MITRE mapping).

**Output-quality issue observed AND fixed, same day**: the live run's
`correlation_decision.merge_into_case_id` pointed at an ID that only existed in Stage 2's
RAG-retrieved `incident_matches` (a similar past incident), not in the real (empty)
`evidence.open_cases` — the model conflated "similar historical case" with "case to merge
into." Fixed with a schema-level enum constraint (primary — `merge_into_case_id`'s allowed
values are now built per-call from the alert's real `open_cases`, live-verified to make the
wrong answer structurally unrepresentable rather than merely discouraged), a system-prompt
clarification (secondary — names `open_cases` vs `incident_matches` explicitly), and a
post-parse cross-check (tertiary, defense-in-depth). Re-verified live end-to-end through the
actual fixed code path against the same evidence that produced the original bug:
`merge_into_case_id: null`, `action: "new"`, 323.2s, captured as
`tests/fixtures/context_live_run_fixed_real.json`. Full detail in CLAUDE.md's "Fixed —
`merge_into_case_id` conflated a RAG match with an open case".

Captured as `tests/fixtures/context_live_run_real.json` (system prompt + real rendered
user prompt + real parsed `ContextualAssessment`). 28 tests, mutation-checked (fallback
MITRE-preservation guard and the `raw_decode`-vs-`json.loads` extraction guard both
confirmed to catch their respective regressions).

### `nodes/rag.py` built — playbook retrieval moved out of Stage 2 entirely

**2026-08-16, same day as `tools/qdrant.py`.** `nodes/rag.py` makes exactly
3 Qdrant calls in parallel — `retrieve_mitre`, `retrieve_incidents`, and a
gated `retrieve_cve` (hardcoded off, see below) — **not 4**. An earlier draft
of this plan had `retrieve_playbooks` here too, queried from `rule_context.
mitre_tactics`. Caught before implementation and corrected:

- **Wrong timing.** Playbook/runbook content (Containment/Remediation
  sections — see the `tools/qdrant.py` entry above on playbooks being
  response runbooks, not reasoning aid) is response guidance, whose natural
  consumer is whatever produces `TriageVerdict.recommended_action` (Stage 4),
  not Stage 2's evidence gathering.
- **Wrong source field.** `rule_context.mitre_tactics` is populated only
  from Sigma `attack.*` YAML tags — Suricata and YARA alerts never have it,
  and plenty of Sigma rules don't either. Querying playbooks from it would
  silently zero out playbook retrieval for a large share of alerts, forever.
  The correct source is Stage 3's confirmed `refined_mitre_mapping`
  (architecture §8), which is populated for every alert regardless of
  engine — from source tags when present (higher confidence) or from Stage
  2's own `mitre_candidates` RAG retrieval when they're absent (lower
  confidence). That field doesn't exist as running code yet (`schemas/
  assessment.py` / `nodes/context.py`, architecture §18 step 5, not started).

**Decision: playbook retrieval is out of scope entirely for now — dropped,
not designed, not stubbed.** No `nodes/playbook_lookup.py` or equivalent
exists anywhere in this repo. `EnrichedEvidence.playbook_matches` was
removed from `schemas/evidence.py` as a result (`PlaybookMatch` itself
stays, defined but currently unused). When playbook retrieval is designed,
it depends on Stage 3 existing first — architecture §18's own build-order
rule applies: *"Each step depends on the previous step's tested contract,
not on assumptions about what a later step will need."*

Also built, unchanged from the original architecture-compliant design:
`_build_mitre_query` (title + `rule_context.description` + one
priority-selected behavioral keyword — `process.api` > `command_line` >
`network` > `file` > `library`, verified live against the real fixture:
T1059.001/PowerShell surfaced as the top real hit for the xordump alert);
`_build_incident_query` (reuses the mitre query verbatim); `_has_cve_
indicators` hardcoded `False` (checked against the one real fixture:
`process.code_signature.subject_name` is `"Microsoft Windows"` throughout —
the OS vendor's cert, not a third-party product; no field anywhere in
`schemas/alert.py` has ever held a genuine third-party product string).

`nodes/gather.py`'s `_guarded`/`_skip`/`_unpack`/`T` were extracted into a
new shared `nodes/_guard.py`, imported by both `gather.py` and `rag.py` —
pure move, `gather.py`'s 9 tests unaffected. `config.STAGE_1_TOOL_TIMEOUT_
QDRANT` is reused explicitly (no new config var), same precedent as
`tools/fp_tracking.py::record_triage_outcome`.

Live-verified 2026-08-16 end-to-end against the real xordump alert
(`sigma-alert-sample.json` + `RuleContext` from `so_detection_5e3cc4d8.json`)
through the real Qdrant + embedding microservice — 5 relevant MITRE
candidates (T1059.001 top, score 0.68), 2 real incident matches (the same
rule's own prior TruePositive/FalsePositive closures), 1 gap (CVE skip),
1.77s stage duration. Captured as `tests/fixtures/rag_live_run_real.json`.
20 tests, mutation-checked (including a regression guard that initially
passed vacuously — the rule title itself contains "Invoke-WebRequest", so an
early version of the command-line-priority test stayed green even with that
branch disabled; fixed to assert on a marker string absent from the title).

### `tools/qdrant.py` built — three existing Qdrant-hit schemas corrected against real data, a 4th collection added

**Verified live 2026-08-16.** Qdrant at `config.QDRANT_URL` (this deployment's
host, `172.20.24.224`, also serves it on `localhost` — same instance, both
reachable), embedding microservice at new required var `config.EMBEDDING_API_URL`
(`172.20.24.224:8001`, `BAAI/bge-m3`, 1024-dim). Four real collections, point
counts confirmed live: `mitre_techniques` 697, `soc_playbooks` 48 (8 runbooks
x ~6 sections), `cve_context` 6,358, `incident_history` 2. `triage_kb` (2,412
points) also exists and is a known test artifact — never queried.

**The existing `MitreCandidate`/`PlaybookMatch`/`CveMatch` schemas (written
earlier from architecture §7's illustrative examples, never live-verified)
did not match the real payload shapes at all.** Corrected in place — nothing
else in the repo consumed them yet, so this was a clean fix, not a breaking
change:

- `MitreCandidate`: real payload has no `description`/`detection_guidance`/
  `priority_score_0_5`; `tactic` is a list, not a string. Real fields kept
  instead: `platforms`, `is_sub_technique`, `parent_technique_id`,
  `x_mitre_version`, `detection_strategy_id`, `analytic_ids`, `log_sources`.
- `PlaybookMatch`: real source is markdown runbooks (zhadyz/AI_SOC) chunked
  by section — `runbook_id`/`title`/`category`/`section`/`document_text`, not
  architecture's structured `investigation_steps`/`verdict_indicators`
  object, which does not exist on any real point.
- `CveMatch`: real payload key is `cvss_score`, not `cvss_v3_score`; has
  `severity`/`published_date`, not `description`/`mitre_technique_ids`/
  `exploit_available`/`cisa_kev`.

This is a third documented instance of architecture's illustrative examples
diverging from live data, alongside RuleContext (§6 tool 2) and
so-ioc-normalize — see the "Known documentation errors" table below, which
should get a fourth row.

**A new `IncidentMatch` schema and `incident_history` collection were added**
— a deployment addition beyond architecture v4 §7's three collections,
maintainer-approved 2026-08-16. It's a semantic-search complement to
`tools/thehive.py::search_closed_cases_by_rule`'s exact rule_uuid match
(same underlying TheHive closed-case data, different retrieval mode), not a
replacement — that tool is unchanged.

**A real bug found and fixed before it shipped**: Qdrant's payload filter on
a keyword field is EXACT match only — confirmed live,
`match: {value: "openssl:openssl"}` → 1 hit, `match: {value: "openssl"}` → 0
hits. `retrieve_cve`'s product narrowing is therefore a CLIENT-SIDE substring
filter over a widened semantic candidate pool, not a Qdrant-side filter. The
first implementation used a small `top_k * 4` candidate pool, which silently
never worked in practice: live-verified that a real matching CVE
(`CVE-2026-31789`, `openssl:openssl`) ranked **48th** by semantic score among
candidates for an on-topic query, since `cve_context` mixes thousands of
CRITICAL CVEs across unrelated products at similar score bands (~0.6–0.66).
Fixed to a fixed 50-candidate pool when a product filter is requested
(~0.4s live-measured, well inside the 3s budget) — regression-guarded by
`TestCveProductFilter::test_product_given_widens_the_candidate_pool`.

Tests: `tests/test_qdrant.py`, 22 tests, real fixture at
`tests/fixtures/qdrant_real.json` (one live `/points/search` response per
collection, captured 2026-08-16). Mutation-checked.

---

## Deferred, agreed, not yet built

| Requirement | Lands in |
|---|---|
| `rule_status_penalty` (`stable=0, test=-10, experimental=-20, deprecated=-30`) in `scoring_config.py`, wired into likelihood in `scoring.py`. Day-one FP signal — `get_fp_signal` starts empty and needs weeks of history; Sigma rule maturity is on the first alert. Absent status scores 0. | Step 7 |
