# SOC-3s — Session Findings, 2026-08-08

Everything flagged during the build session of 2026-08-08, with evidence and
current status. Open items are collected at the end.

Companion documents:
- `CLAUDE.md` — operating rules and the ground-truth hierarchy
- `REPO-STATUS.md` — verified deployment facts and build progress

**Status key:** ✅ resolved in code · 🟦 decided, no code change needed ·
⚠️ **open — needs action**

Session scope: build-order steps 1 and 2a–2c/2e. Test count 0 → **149**.

---

## 1. Configuration and environment

| # | Finding | Evidence | Status |
|---|---|---|---|
| 1.1 | `.env` was empty (0 bytes) | — | ✅ populated |
| 1.2 | **`ES_URL` had no port.** `https://172.20.24.58` → HTTP 302 (SOC web UI on 443); `:9200` → HTTP 200 | live curl | ✅ fixed; `config.py` now raises at import if the port is absent |
| 1.3 | **`qwen3.5:4b` is not deployed.** Ollama serves only `foundation-sec-reasoning:latest` and `llama3.2:3b`, but architecture §19 assigns qwen to Stage 3 | `/api/tags` | 🟦 both stages run `foundation-sec-reasoning`. Stage 3 ~30-60s → ~60-90s, p95 end-to-end → ~200s, inside the 300s n8n budget with less margin than the two-model design assumed |
| 1.4 | `LLM_ANALYZE_BASE_URL` / `_MODEL` / `_API_KEY` absent from `.env` | §19 | ✅ added |
| 1.5 | `FP_TRACKING_DB_PATH` vs architecture §19's `FP_DB_PATH` | — | ✅ both accepted, deployment name wins |
| 1.6 | `CORTEX_URL` / `CORTEX_API_KEY` absent | §6, §13 | 🟦 intentional — this service never calls Cortex |
| 1.7 | Redis not deployed | — | 🟦 accepted; Stage 0 dedup no-ops per §5, duplicates inside the window get processed more than once |
| 1.8 | Architecture §6's gather pseudocode uses `alert.host.name`; §5's dedup fingerprint and `alert_builder` use `host.hostname` | doc vs code | 🟦 standardised on `hostname` |

---

## 2. Errors found in the design documents

All caught by live backend calls. The docs are authoritative on *intent*;
they have proven unreliable on *field names and response shapes*.

| # | Document | Claim | Reality |
|---|---|---|---|
| 2.1 | Impl. guide §0.2 | Security Onion "does have a `so-ioc-normalize` ingest pipeline" | It is a **custom** pipeline. Its own description says it runs *after* "Security Onion's own … chain". §0.2's conclusion still binds; only its attribution is wrong |
| 2.2 | Impl. guide §0.2 | Fetch Cortex reports with `extraData: ["reports"]` | **Silently dropped** by TheHive 5.6.1. Reports live only on Job objects at `/api/connector/cortex/job/{id}` |
| 2.3 | Arch. §6 tool 2 | Example `RuleContext` | Differs four ways — see §4.1 below |
| 2.4 | Arch. §6 tool 5 | `AssetContext` with `network_zone`, `data_sensitivity`, `owner` | **None of the three exist** on any class in this iTop |
| 2.5 | Arch. §6 tool 4 | `search_closed_cases_by_rule(rule_uuid, …)` | **Rule uuid is not searchable** in TheHive — no such attribute on Case or Alert, no customFields |
| 2.6 | Arch. §18 | Enumerated schema model list | Confirmed by the maintainer as illustrative, not a ceiling |

---

## 3. Reference material

| # | Finding | Status |
|---|---|---|
| 3.1 | **`ingest-templates.txt` is misnamed.** It is not ingest templates — it is a live `logs-detections.alerts-so/_mapping` dump across 24 backing indices (2026.06.21 → 07.16): 438 `event_data.*` leaf fields plus 29 top-level | 🟦 documented in `CLAUDE.md` |
| 3.2 | It carries field **names and types only, never values** — so it can never tell you which `event.dataset` a shape belongs to. The eight dataset names were grepped for and returned **0 hits each** | 🟦 documented; dataset inventory came from the maintainer |
| 3.3 | **My own error, corrected:** I reported "only 1 of 24 backing indices has an `ioc` mapping" as evidence of rarity. That dump ends 2026-07-16 — the exact day the pipeline went live. The count measured **recency, not rarity** | ✅ corrected in `CLAUDE.md` and memory |
| 3.4 | `so-alert-reference/` had no `CONTEXT.md` | ✅ created with the build-time-only note |
| 3.5 | The compiled ElastAlert YAML strips MITRE tags — never useful ground truth for `detection_rule_lookup` | 🟦 confirmed by maintainer; tags live in `so_detection.content` |
| 3.6 | **The prior 160 `alert_builder` tests no longer exist** | 🟦 confirmed gone; the 149 tests written this session are the baseline |

---

## 4. Backend findings

### 4.1 Elasticsearch — `so-detection`

| # | Finding | Status |
|---|---|---|
| 4.1.1 | **`so-detection*` must never be wildcarded.** It also matches `so-detectionhistory` — 345,474 revision docs alongside 74,951 current rules — so a wildcard can return a superseded rule version | ✅ index pinned exactly |
| 4.1.2 | **`source_engine` comes from `so_detection.language` ("sigma"), not `engine` ("elastalert")** — the latter is the *execution* engine. Reading it would send every rule down the wrong parse branch | ✅ |
| 4.1.3 | **Doc-level `tags` is `null`.** MITRE exists only inside `content` (the original Sigma YAML), as `attack.t1105` / `attack.command-and-control` | ✅ YAML-parsed and normalised to `T1105` |
| 4.1.4 | **Sigma `tags:` is not only techniques and tactics.** It also carries ATT&CK group ids (`attack.g0016`), software ids (`attack.s0002`), `cve.*` and `car.*` refs. Treating all non-techniques as tactics would have fed Stage 3 things that are not tactics | ✅ split into `mitre_groups`, `mitre_software`, `other_tags` |
| 4.1.5 | **`falsepositives: ["Unknown"]`** — Sigma's placeholder for "none documented". Passing it through makes the LLM reason about an FP condition literally named "Unknown" | ✅ derived `has_known_falsepositives` boolean; raw list kept for audit |
| 4.1.6 | Sigma `status:` (stable/test/experimental/deprecated) is a **day-one FP signal** — unlike `get_fp_signal`, which starts empty and needs weeks of history | ✅ captured as `status` + `has_reliable_status`; penalty deferred to step 7 |

### 4.2 iTop — implementation guide §3 gate

Ran and reported. Asset resolves (`PC::32`, `business_criticity = "medium"`), so
it does **not** hit §3's literal stop condition — but is the same situation in
practice.

| # | Finding | Status |
|---|---|---|
| 4.2.1 | **CMDB is 32 CIs, of which 31 are iTop's stock demo fixtures** (Apache, CRM, ERP, ESX1-3, Server1-4, VM1-4, Rack1, Router1, Switch1…). Only `win-kvkmd51ggkq` is real | ⚠️ see §6 |
| 4.2.2 | `criticality` is `medium` — the formula's own baseline, so it discriminates nothing today | ⚠️ see §6 |
| 4.2.3 | **`network_zone` does not exist** on any class; IP Management extension absent (`IPv4Subnet` is not a valid class) | 🟦 always `None`, gap logged. No subnet maps in config or scoring |
| 4.2.4 | **`data_sensitivity` does not exist** on any class | 🟦 always empty |
| 4.2.5 | **`owner` does not exist.** `contacts_list` empty; **zero contact links in the entire CMDB** | 🟦 always `None` |
| 4.2.6 | **IP lookup is impossible.** `PhysicalInterface` and `NetworkInterface` both return 0 rows; no object carries an IP | 🟦 hostname + `asset_number` are the only keys |
| 4.2.7 | **`asset_number` holds the Elastic Agent host UUID** and matched `event_data.host.id` exactly — a stable join key, strictly better than hostname (case-sensitive in OQL `=`, breaks on FQDN vs short name) | ✅ primary lookup |
| 4.2.8 | **`output_fields: "*"` returns only the attributes of the class you query.** `FunctionalCI` omits `asset_number`; `PhysicalDevice` omits `osfamily_name` | ✅ two-phase locate-then-refetch-on-`finalclass` |
| 4.2.9 | **A real bug the live run caught:** the refetch compared `finalclass` against `obj["class"]`, which iTop populates with the object's *actual* class — so they always matched and the refetch **silently never fired**, losing `os_family`/`asset_type` and, on the hostname path, `asset_number` itself | ✅ fixed; regression-guarded. Mocked-tests-first would have frozen the bug in as correct |
| 4.2.10 | `asset_number` is **not filterable on `FunctionalCI`** ("Unknown filter code") and does not exist on `VirtualMachine` at all — VMs are not `PhysicalDevice`, so only the hostname fallback reaches them | ✅ |
| 4.2.11 | iTop returns **HTTP 200 with a non-zero `code`** for API errors — `raise_for_status()` alone swallows every one | ✅ |
| 4.2.12 | **OQL injection.** Hostnames come from Security Onion telemetry (attacker-influenceable) and were interpolated into an OQL string — `win-kvkmd51ggkq" OR 1=1 OR name="` was live | ✅ values rejected, not escaped (`^[A-Za-z0-9._:-]{1,255}$`); 6 injection tests |
| 4.2.13 | `business_criticity` enum was **queried, not guessed**: low (27), medium (2), high (3). OQL does not validate enums in `WHERE`, so this is observed, not schema-derived | 🟦 unseen values pass through and log, never coerced |

### 4.3 TheHive

| # | Finding | Status |
|---|---|---|
| 4.3.1 | **0 cases** (vs 3,640 alerts, 533,373 observables). Both case tools return empty for every alert; `correlation_mode` is always `"new"` | 🟦 correct real result per guide §2 |
| 4.3.2 | **`stage` and `status` are different vocabularies.** `stage = New\|InProgress\|Closed`; `status = New\|InProgress\|TruePositive\|FalsePositive\|Duplicated\|Indeterminate\|Other`. **There is no `Closed` status** — filtering status for openness silently matches everything | ✅ filters `stage`; test asserts no status filter appears |
| 4.3.3 | **Rule uuid is not searchable.** Matching falls back to the `rule:<name>` tag plus shared observables | ✅ `matched_by` records which ran; uuid-only input returns an explicit gap |
| 4.3.4 | **TheHive returns epoch milliseconds.** Pydantic parses a bare int as *seconds* — every case would have been dated to 1970, silently breaking recency reasoning | ✅ converted explicitly, regression-guarded |
| 4.3.5 | Empty results prove nothing — a broken query also returns empty. Identical shapes run against the Alert graph returned **99** and **12** | ✅ pinned as shape proof in the fixture |
| 4.3.6 | Case `severity` is `1..4`, TLP `0..4` — not the 0-100 scale used elsewhere | 🟦 no conversion in the tool; `scoring.py` owns it at step 7 |

### 4.4 Cortex

| # | Finding | Status |
|---|---|---|
| 4.4.1 | `extraData: ["reports"]` is **silently dropped** — `seen`, `shareCount`, `permissions`, `links` all return, `reports` never does. Report bodies exist only on Job objects | 🟦 see 4.4.3 |
| 4.4.2 | **No report has `summary.taxonomies`.** All five analyzers with successful jobs return keys `['artifacts','full','success']`. `alert_builder._build_cortex_results` reads `report["summary"]["taxonomies"]`, so `cortex_results` is **structurally always empty** and §10's `threat_intel_adjustment` is permanently **0** | ⚠️ see §6 |
| 4.4.3 | Underlying data is present but unsummarised (VirusTotal `full` carries `reputation`, `sandbox_verdicts`, `last_analysis_stats`) | 🟦 **n8n will attach report bodies to the `/triage` payload** — consistent with §6, which already says Stage 1 never calls Cortex |
| 4.4.4 | TheHive's alerts were **not all created by the n8n workflow**, so absent reports on them is not evidence of a broken pipeline | 🟦 noted |

### 4.5 Security Onion / n8n

| # | Finding | Status |
|---|---|---|
| 4.5.1 | **`ioc.*` is not a Security Onion field** — written by the custom `so-ioc-normalize` pipeline, which sets `ioc.source_engine = ctx.event.module` and therefore can never corroborate it | ✅ never read; two regression guards |
| 4.5.2 | **That pipeline is LIVE.** `ioc.*` is on 100% of alerts from 2026-07-16 onward (5,571 of 7,719); 0% before. A fresh pull still contains it | 🟦 rule is "present but never read", not "absent" |
| 4.5.3 | Engine detection uses `event.module`, then the `event.dataset` prefix — confirmed from `securityonion-es.py` and by aggregation (100% `sigma` / `sigma.alert`, 7,719 docs) | ✅ |
| 4.5.4 | **n8n observable extraction mislabels dataTypes.** On alert `~1190993992`: an observable typed `url` contains the **entire PowerShell command line**; one typed `domain` contains a **URL** | ⚠️ see §6 |
| 4.5.5 | The webhook body differs from the ES document by exactly six keys the alerter/n8n layer adds: `_id`, `_index`, `num_hits`, `num_matches`, `severity_filter`, `source_system`. Every shared key is identical | 🟦 documented |
| 4.5.6 | **Alert/event timestamp skew.** Alert `@timestamp` and `event_data.@timestamp` differ by ~2 days in real samples. Architecture §10's `evidence_age_hours > 24` branch does not say which it means | ⚠️ see §6 |

---

## 5. Schema and extraction work

| # | Finding | Status |
|---|---|---|
| 5.1 | `alert_builder.py` imported a `schemas` package that did not exist — the module was unimportable | ✅ `schemas/alert.py` + `__init__.py` built from its actual usage |
| 5.2 | **Stale docstring:** `_parse_rule` claimed Sigma alerts carry no top-level `rule` dict. They do (`rule.{name,uuid,product,category}`) | ✅ corrected |
| 5.3 | `event_data.file.*` and `event_data.dll.*` had **no extractors** — `endpoint.events.file` yielded `file=None`, `endpoint.events.library` had no path at all | ✅ added; `dll` → new `Library` model, not folded into `File` |
| 5.4 | `event_data.process.Ext.api.*` (`endpoint.events.api`) unmapped — the primary **process-injection** evidence surface | ✅ added as `ApiCall` |
| 5.5 | `event_data.Target.process.*` unmapped — a **second, distinct process** (cross-process access) | ✅ added as `target_process` |
| 5.6 | `event_data.related.*` (ECS entity roll-ups) unmapped | ✅ carried on `related_entities`, **deliberately not merged into `observables`** — guide §0.2 makes `hive_alert.observables` the single IOC source of truth |
| 5.7 | `host.ip` is absent in the real alert; the agent address is at `event_data.metadata.input.beats.host.ip` | ✅ fallback added |
| 5.8 | Fields deliberately **not** mapped, named rather than dropped: `process.session_leader.*` (Linux), `tty`/`uptime`/`title`, `http.request.headers.*`, `Endpoint.policy.applied.*`, `winlog.event_data.*` duplicates, second-order file metadata | 🟦 listed for review |

---

## 6. ⚠️ Gaps that need fixing in the future

Ordered by impact on whether the system produces a defensible score.

### 6.1 — ~~`threat_intel_adjustment` is permanently 0~~ · ✅ **RESOLVED 2026-08-09**

Solved by the custom TheHive Function `getAlertWithObservables`, which returns
`reports[analyzer].taxonomies` in one call. `cortex_results` now populates
correctly (0 → 4 on the reference alert).

Two fixes were needed alongside it:
- `_build_cortex_results` now accepts both `report["taxonomies"]` (Function) and
  `report["summary"]["taxonomies"]` (Cortex API).
- `_summarize_taxonomies` now derives the verdict from detection-ratio rows
  rather than `max(level)`, which had been scoring `github.com` and signed
  `powershell.exe` as malicious/90.

**Residual risk:** the Function is custom server-side JS, not stock TheHive. Its
definition is preserved in `thehive-reference/` and the tool degrades to an
actionable `Gap` if it disappears. **Re-verify after any TheHive upgrade.**

### 6.2 — `impact` scoring is a constant · **blocker for queue ordering**

iTop holds one real asset at `criticality: medium`, with no `network_zone`,
`data_sensitivity` or `owner` on any class. Three of the four inputs to
`base_impact` are unavailable and the fourth never varies.

**Needs:** CMDB population — real assets, criticality tiers, and custom fields
for zone and sensitivity. **Owner: maintainer, deferred until sensors are
deployed.** Architecture §17 already calls this the single biggest deployment
risk; §16 lists it as a day-1 prerequisite.

**Until then:** `impact` contributes a fixed value to every alert, so priority
ordering is driven by likelihood and confidence alone. The tool is built
correctly and works the moment data appears.

### 6.3 — Historical priors are empty · expected, self-resolving

0 cases in TheHive, so `search_closed_cases_by_rule` returns zeros and
`correlation_mode` is always `"new"`. Architecture §6 expects this for ~30 days
and says it becomes the second-strongest signal after ~3 months. **No action —
it resolves through usage.** Worth re-verifying against real cases once they
exist, since the case-shaped test fixtures are synthetic.

### 6.4 — ~~n8n is emitting a junk observable~~ · ✅ resolved upstream

The command-line-as-`url` observable is gone as of 2026-08-09. Current
observables on alert `~4168` are clean: the xordump URL, `github.com`, sha256,
imphash. No action needed.

### 6.4b — historical: n8n was emitting a junk observable

An observable typed `url` contains an entire PowerShell command line. It will
land in `observables.urls`, be sent to Cortex as a URL, and reach Stage 3 as an
IOC. `alert_builder`'s `URL_RE` rescues the mislabelled *domain* but cannot
rescue this one.

**Needs:** fix the extraction regex in the n8n Alert Builder node. Outside this
repo. **Owner: maintainer.**

### 6.5 — `evidence_age_hours` is undefined

Alert `@timestamp` and `event_data.@timestamp` differ by ~2 days. §10's
velocity multiplier down-weights evidence older than 24h, but does not say which
timestamp it means — against alert time the sample is fresh, against event time
it is stale and gets `0.8×`.

Both are carried on `CanonicalAlert` so nothing is lost. **Decision needed at
build step 7.**

### 6.6 — `rule_status_penalty` not yet wired

Agreed: `stable=0, test=-10, experimental=-20, deprecated=-30`, absent scores 0.
Input (`RuleContext.status`) is extracted and live-verified. **Lands in step 7**
with `scoring_config.py` / `scoring.py`.

### 6.7 — Secrets are unprotected

`.env` holds live TheHive, iTop and Elasticsearch credentials. The directory is
**not a git repo**, so there is no `.gitignore` yet. `.env` must be ignored
before the first commit; `.env.example` already carries the key names only.

### 6.8 — The TheHive API key is over-privileged

The key authenticates as `analyst@trustshield.local` with the `org-admin`
profile, carrying `manageCase/create`, `manageAlert/update` and similar **write**
permissions. Architecture §1 and §14 state this service is **read-only by
construction** — all case-modifying actions happen in n8n after human review.

Nothing in this repo writes, but the credential permits it. **Recommend a
read-only TheHive profile for the agent-service key**, so the guarantee is
enforced by the platform rather than by code review.

### 6.9 — Non-Sigma paths cannot be integration-verified

Only Sigma fires (`event.module = "sigma"`, 100% of 7,719 alerts). Suricata,
Strelka and YARA extraction, and the non-Sigma `detection_rule_lookup` branches,
are unit-tested against **synthetic fixtures only** and marked as such
throughout. This is the expected state per guide §0.1, not an incomplete build.
**Re-verify when sensors are deployed.**

### 6.10 — ~~`get_full_alert_with_analysis` is unbuilt~~ · ✅ **RESOLVED 2026-08-09, REWRITTEN 2026-08-13**

Built against the custom Function, live-verified, 9 tests. Returns the alert,
its observables (the §0.2 IOC source) and their Cortex taxonomies in one call.

**2026-08-13 update:** the custom Function this depended on is gone (TheHive
moved to 172.20.24.228, upgraded to 5.7.5-1, `404 Function
getAlertWithObservables not found`). Rewritten to two concurrent stock
`/api/v1/query` calls — the external-API limitation that required the custom
Function in the first place no longer holds on this version. See
`REPO-STATUS.md`'s "TheHive moved AGAIN" entry and `thehive-reference/
CONTEXT.md`'s historical section.

### 6.11 — Documentation drift

The four doc errors in §2 are recorded in `CLAUDE.md` and `REPO-STATUS.md` but
**not corrected in the source documents**. A future reader of
`SOC-3s-IMPLEMENTATION-GUIDE.md` §0.2 will still be told `so-ioc-normalize` is a
Security Onion pipeline and that `extraData: ["reports"]` works. Worth patching
the guide itself.

## 7. Session of 2026-08-13 — regression fix, TheHive move, OpenCTI tool

Picked back up after a gap. Three things needed attention, none discovered by
searching for problems — the first was a real regression found by simply
running the existing suite.

### 7.1 — `CortexResult` regression: 8 tests failing on session start · ✅ RESOLVED

`schemas/alert.py`'s `CortexResult` had been redesigned (2026-08-10) to drop
`score` and turn `verdict` into a `list[str]`, closing a real hard-constraint
violation. `alert_builder.py` was never updated to match — `_build_cortex_
results` still built the old shape, failing Pydantic validation on every
Cortex-bearing alert. Fixed; see `REPO-STATUS.md`'s "`CortexResult.verdict`
fixed" entry for the resulting (deliberate) verdict-rule change.

### 7.2 — TheHive moved again, custom Function retired · ✅ RESOLVED

See `REPO-STATUS.md`'s "TheHive moved AGAIN" entry and finding 6.10 above.

### 7.3 — `tools/opencti.py` built, a deployment-added Stage-1 tool · ✅ RESOLVED

User-requested. Not in architecture v4's original 7 tools. Live-verified
against OpenCTI GraphQL 7.260318.0. See `REPO-STATUS.md`'s "OpenCTI is
reachable" entry and CLAUDE.md's "OpenCTI" deployment decision.

### 7.4 — `.mcp.json`'s OpenCTI token had a typo · ✅ RESOLVED

`lgrn_octi_tkn_...` (missing leading `f`) 401s; corrected to
`flgrn_octi_tkn_...` in both `.mcp.json` and `.env`'s new `OPENCTI_TOKEN`.
Found via a user-supplied working curl command, not independently discovered.

### 7.5 — `CORTEX_API_KEY` still 401s · 🟦 not investigated further

Re-checked 2026-08-13 against `/api/analyzer` (400) and `/api/job?range=...`
(401). Unused at runtime by design either way (§6.10 above / CLAUDE.md).
Not blocking anything live; flagged here in case it matters if the direct-
Cortex fallback is ever actually needed.
