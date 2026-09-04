# The Threat-Intel Path — What Was Built, and Why

Built 2026-08-09. Covers how Cortex analyzer verdicts reach
`CanonicalAlert.cortex_results`, and how that value is derived.

This is the input to `threat_intel_adjustment` in architecture §10's likelihood
formula — a **−40 to +30** term, the widest single range in the whole formula.
Before this work it was structurally always **0**.

Related: `REPO-STATUS.md` (deployment facts) · `SESSION-FINDINGS.md` (all
findings) · `thehive-reference/CONTEXT.md` (the Function dependency, now
historical).

**UPDATE 2026-08-13 — two things below are stale, kept for history, not
corrected in place (ground-truth hierarchy: a tier-1 finding can go stale and
needs a dated update, not silent deletion):**

1. **§1's "three routes all fail" finding is TheHive-5.7.3-specific and no
   longer true.** TheHive moved again and was upgraded to 5.7.5-1
   (172.20.24.228). The stock `getAlert -> observables -> page` projection now
   returns `reports[analyzer].taxonomies` directly — confirmed live against a
   real alert. The custom Function §1 concludes is required is **retired**;
   `tools/thehive.py::get_full_alert_with_analysis` no longer calls it. See
   `thehive-reference/CONTEXT.md`'s historical section and CLAUDE.md's
   "TheHive moved and was upgraded again" entry.
2. **`CortexResult.score` no longer exists**, and the verdict-collapsing rule
   this document's §"verdict-aggregation trap" describes (parse a detection
   ratio, threshold it, override the analyzer's own `level`) was itself
   retired 2026-08-13 — that parsing step computed a judgement outside
   `scoring.py`, the same class of hard-constraint violation this document's
   own fix was originally about. The CURRENT rule: `verdict` is a `list[str]`,
   taking every taxonomy row's `level` at face value with no override; the
   github.com scenario below is preserved as a still-valid illustration of
   *why the collapsing trap is real*, but its conclusion ("scores
   clean/5") no longer matches current code — see `REPO-STATUS.md`'s
   "`CortexResult.verdict` fixed" entry and `alert_builder.py::
   _summarize_taxonomies`'s current docstring for the full reasoning.

---

## 0. The problem in one paragraph

`alert_builder._build_cortex_results` read `report["summary"]["taxonomies"]`
from `hive_alert.observables[].reports`. Neither half of that existed:
TheHive's external API does not put `reports` on observables at all, and the
report bodies it *does* expose (via the Cortex connector endpoint) contain no
`summary`. So the loop never executed its body, `cortex_results` was always
`[]`, and every alert was scored as though every IOC were unknown — silently,
with no error and no gap.

---

## 1. Where the data actually lives

Three documented or obvious routes were tried on TheHive 5.7.3. All three fail:

| Route | Result |
|---|---|
| `extraData: ["reports"]` on observables — implementation guide §0.2's documented method | Key **silently dropped**. Six spellings tried (`reports`, `report`, `analyzerReports`, `cortexReports`, `miniReports`, `jobs`); `shares` and `seen` return fine, so `extraData` itself works |
| `extraData: ["report"]` on jobs | Returns a report — `['artifacts','full','success']`, **no `summary`** |
| `GET /api/connector/cortex/job/{id}` | Same three keys, `summary: null` |

The string `taxonomies` appears nowhere in any of those payloads, checked at top
level and nested inside `full`, for both `VirusTotal_GetReport` and
`VirusTotal_Rescan`.

**What works** is a custom TheHive *Function* — server-side JavaScript
registered on the instance:

```
POST {THEHIVE_URL}/api/v1/function/getAlertWithObservables
{"alertId": "~4168"}
```

It returns the alert, its observables, and `reports[analyzer].taxonomies`, in
**one call**.

### Why the Function sees data the API does not

The Function body calls `context.query.execute([...])` — TheHive's **internal**
query engine. That engine's observable serialiser includes `reports`. The
external `/api/v1/query` endpoint uses a *different* serialiser that strips
them. Two serialisers, one product. This is not a version quirk and not
something a different `extraData` key can reach.

### Cortex-direct was evaluated and rejected

`{cortex}/api/job/{cortexJobId}/report` (Cortex 4.0.1 at
`http://172.20.24.221:9001/cortex`) **does** return `summary.taxonomies`, plus
the raw `full` blob. It was rejected deliberately:

| | Function | Cortex direct |
|---|---|---|
| HTTP calls per alert | **1** | ~10–14 |
| Taxonomies | ✅ | ✅ identical |
| `full` raw report | ❌ | ✅ |
| Credentials | TheHive only | TheHive **+ Cortex** |
| Backends in §13's inventory | 1 | 2 |
| Architecture §6/§13 "never calls Cortex" | preserved | **violated** |

The only thing Cortex-direct adds is `full` — and architecture §9 forbids
passing it downstream. Stage 4 sees `details_truncated_300`; a VirusTotal `full`
blob is tens of KB and would be discarded at the stage boundary. Fetching a
large attacker-influenceable blob in order to throw it away is a cost with no
benefit and an added prompt-injection surface.

`CORTEX_URL` / `CORTEX_API_KEY` remain in `.env`, unused, as the documented
fallback if the Function is ever lost.

---

## 2. Component 1 — `get_full_alert_with_analysis`

`tools/thehive.py`. Architecture §6 and implementation guide §0.2 name this as
the single source of **both** the IOC list and the pre-computed threat-intel
verdicts. Its return value is handed straight to
`alert_builder.build_canonical_alert(..., hive_alert=<this>)`.

```python
async def get_full_alert_with_analysis(
    thehive_alert_id: str, timeout: float | None = None
) -> tuple[dict | None, Gap | None]:
```

### It never raises

Every Stage-1 tool must return a typed `Gap` instead of throwing, because
`nodes/gather.py` runs them inside `asyncio.gather(..., return_exceptions=True)`
and an escaping exception becomes an opaque entry in a results list. The
contract here is `(hive_alert | None, Gap | None)` — one or both populated, never
an exception.

### The missing-Function case is *actionable*, not just handled

```python
if response.status_code == 404:
    return None, gap(
        f"TheHive Function '{THEHIVE_ALERT_FUNCTION}' is not registered. "
        f"Re-register it from thehive-reference/{THEHIVE_ALERT_FUNCTION}.json — "
        f"without it there is no threat-intel signal."
    )
```

This matters because the Function is **custom server-side JS, not stock
TheHive**. A TheHive upgrade, an org rename, or a wiped config can remove it,
and nothing else in the system would notice — threat intel would simply go quiet
again, exactly the failure this whole exercise was fixing. So the gap names the
file that can restore it. The pipeline continues with no TI rather than failing
the alert, per architecture §15 (never 5xx to n8n).

### The `stderr` check, and why HTTP status is not enough

The Function is JavaScript executing inside TheHive. When that JS throws — say
the alert id does not exist — TheHive still returns **HTTP 200**, with the error
on `stderr` and `result: null`:

```python
stderr = (payload or {}).get("stderr") or ""
result = (payload or {}).get("result")
if not isinstance(result, dict):
    detail = stderr.strip() or f"unexpected payload keys {sorted((payload or {}).keys())}"
    return None, gap(f"{THEHIVE_ALERT_FUNCTION} returned no usable result: {detail}")
```

`raise_for_status()` alone would treat a thrown JS error as success and return an
empty alert. A partial success — result present *and* stderr non-empty — returns
the data **and** a gap, so the audit trail records that something went wrong
without discarding usable evidence.

### Distinguishing "no IOCs" from "could not fetch"

An alert with zero observables returns the alert plus a gap saying so. That
keeps architecture §2 requirement 4 intact: `{found: false}` must never mean two
different things. "This alert genuinely has no IOCs" and "we failed to retrieve
them" produce different, readable gap reasons.

---

## 3. Component 2 — `_build_cortex_results` accepts both report shapes

Two real shapes exist for the same data:

```
TheHive Function      report["taxonomies"]
Cortex API / classic  report["summary"]["taxonomies"]
```

```python
taxonomies = report.get("taxonomies")
if taxonomies is None:
    taxonomies = _as_dict(report.get("summary")).get("taxonomies")
if not taxonomies:
    continue
```

Accepting both means the *source* can change — Function today, Cortex-direct or
an n8n-attached payload tomorrow — without touching this function. The old code
read only the second shape, which is why `cortex_results` was empty: the Function
supplies the first.

Note `.get("taxonomies")` is checked against `None`, not falsiness, so an
analyzer that legitimately returns `"taxonomies": []` is not mistaken for "wrong
shape, try the other one".

---

## 4. Component 3 — `_summarize_taxonomies`, the verdict rule

This is the part with real judgement in it.

### The trap

VirusTotal emits **several taxonomy rows per observable**, and `level` colours
**that row**, not the observable. Real data from alert `~4168`:

| observable | row 1 | row 2 |
|---|---|---|
| `github.com` | `56 resolution(s)` **[malicious]** | `0/91` *[info]* |
| `powershell.exe` sha256 | `6 contacted domain(s)` **[malicious]** | `0/74` *[info]* |
| xordump URL | `3/97` [malicious] | — |

Row 1 in each case is **context**: "this domain has 56 DNS resolutions, some
touching flagged infrastructure". For a domain hosting millions of repositories
that is unremarkable. Row 2 is the **verdict**: 0 of 91 engines flag github.com.

Both rows are accurate. VirusTotal is right about both. **The taxonomies are
trustworthy — the way they were being collapsed was not.**

The old implementation was one line:

```python
worst = max(taxonomies, key=lambda t: _LEVEL_SCORES.get(t.get("level"), 0))
```

"Take the worst level across all rows and call that the observable's verdict."
That is correct when an analyzer emits one row. With several, it picks the
context row and discards the verdict row. Result:

```
github.com   -> malicious (90)
powershell.exe sha256 -> malicious (90)
```

### Why that is worse than having no threat intel

Almost any real observable has *some* context row tagged malicious. So
`threat_intel_adjustment` would sit near its **+30 maximum on essentially every
alert**. An always-empty field is visibly a gap that someone eventually
investigates. An always-+30 field looks like working evidence and quietly
inflates every likelihood score — including for Microsoft-signed system
binaries.

### The rule

**A detection-ratio row (`N/M`) is the verdict. Everything else is context.**

```python
detections: list[int] = []
for t in taxonomies:
    match = _RATIO_RE.match(str(t.get("value", "")))
    if match:
        detections.append(int(match.group(1)))

if detections:
    worst = max(detections)
    if worst >= _TI_DETECTIONS_MALICIOUS:      # 5
        return "malicious", 90, details
    if worst >= _TI_DETECTIONS_SUSPICIOUS:     # 1
        return "suspicious", 55, details
    return "clean", 5, details

worst_row = max(taxonomies, key=lambda t: _LEVEL_SCORES.get(t.get("level"), 0))
```

`_RATIO_RE = re.compile(r"^\s*(\d+)\s*/\s*(\d+)\s*$")` — anchored, so
`"56 resolution(s)"` cannot match and be mistaken for a ratio.

### Three deliberate properties

**1. The `level` fallback is kept.** If no ratio row exists, the old behaviour
applies. Analyzers like MISP report `MISP:hits=2 (suspicious)` with no ratio, and
there the level genuinely *is* the verdict. The trap only arises when ratio and
context rows coexist — removing the fallback would break every analyzer that
never emits ratios.

**2. Context rows are preserved, not discarded.** All rows, including the
demoted ones, go into `CortexResult.details` verbatim:

```
VT:GetReport=56 resolution(s) (malicious); VT:GetReport=0/91 (info)
```

They are demoted from deciding the verdict, not deleted. Stage 3 and the audit
trail still see them.

**3. Duplicates are collapsed first.** The real payload carries
`VT:GetReport=3/97` and `VT:Scan=1/92` **each exactly twice**. `_dedupe_taxonomies`
keys on `(namespace, predicate, value, level)`. Without it a single datapoint is
double-weighted, and `details` reads as though two independent analyses agreed.

### Thresholds

```python
_TI_DETECTIONS_SUSPICIOUS = 1   # >= 1 engine flagged it
_TI_DETECTIONS_MALICIOUS  = 5   # >= 5 engines flagged it
```

Educated starting values, in the spirit of architecture §17 (all scoring
constants expect 30–60 days of tuning against analyst feedback). One engine
flagging something is common and weak; five is a real signal. **Candidates to
migrate into `scoring_config.py` at build step 7.**

---

## 5. Live verification

Against the real alert `~4168`, through the real Function, into a real
`CanonicalAlert`:

```
cortex_results: 0 → 4

  https://github.com/audibleblink/xordump/…   VirusTotal_GetReport_3_1  suspicious  55
     details: VT:GetReport=3/97 (malicious)
  https://github.com/audibleblink/xordump/…   VirusTotal_Scan_3_1       suspicious  55
     details: VT:Scan=1/92 (malicious)
  1c84c8632c5269f24876ed9f49fa810b49f77e1e…   VirusTotal_GetReport_3_1  clean        5
     details: VT:GetReport=6 contacted domain(s) (malicious); VT:GetReport=0/74 (info)
  github.com                                  VirusTotal_GetReport_3_1  clean        5
     details: VT:GetReport=56 resolution(s) (malicious); VT:GetReport=0/91 (info)
```

Every one is correct:

- **xordump URL — suspicious.** It genuinely is offensive tooling and 3 of 97
  engines flag it. The fix does not blunt the real signal.
- **`powershell.exe` sha256 — clean.** 0 of 74. Microsoft-signed system binary.
- **`github.com` — clean.** 0 of 91.
- The fourth observable (imphash `bf7a6e7a…`) had no analyzer run against it, so
  it correctly produces no result rather than an "unknown" row.

Observable extraction alongside it (the §0.2 IOC path):

```
urls    ['https://github.com/audibleblink/xordump/releases/download/v0.0.1/xordump.exe']
domains ['github.com']
sha256  ['1c84c8632c…']
imphash ['bf7a6e7a62…']
```

---

## 6. Mutation testing — what it is and why it was run

### The problem it solves

A passing test suite proves the tests pass. It does **not** prove the tests
would notice if the code broke. A test can pass for the wrong reason —
asserting on a field the code never populates, or on a value that happens to be
the default. This is the same class of failure implementation guide §6 warns
about when it says green mocks and a working pipeline are *different claims*.

Fixture-backed tests are especially prone to it: a fixture with rich real data
makes almost any assertion look meaningful.

### The method

Deliberately break the production code, run the tests, and confirm they go
**red**. If a mutation survives — code broken, tests still green — that region
is effectively untested regardless of how many assertions cover it. Then restore
the code and confirm green again.

The restore step matters as much as the break: it proves the red was caused by
the mutation and not by something incidental left behind.

### The three mutations, and what each was probing

**Mutation 1 — revert the verdict rule to `max(level)`**

```python
if detections:        →    if False:
```

Bypasses the ratio branch entirely, falling through to the old worst-level
logic. This is not a random edit — it is *the exact bug that existed before this
work*. The question being asked: if someone later "simplifies" this back, or a
bad merge reverts it, will anything catch it? A ratio-verdict rule with no test
that fails when it is removed is decoration.

**Mutation 2 — drop the no-`summary`-wrapper shape**

```python
taxonomies = report.get("taxonomies")   →   taxonomies = None
```

Forces the code down the `report["summary"]["taxonomies"]` path only — the
original behaviour, which produces zero results against Function payloads.
Probing: does anything detect that the Function's shape has stopped being read,
or does `cortex_results == []` slip through as though the alert simply had no
threat intel? This is the silent-failure mode that made the original bug
invisible for so long.

**Mutation 3 — disable de-duplication**

Left dedup out of the collapse path. Probing whether the duplicate-collapse
assertion is real or incidental — with `3/97` appearing twice in the payload,
`details.count("3/97") == 1` only passes if dedup actually runs.

### Result

```
7 failed, 56 passed

FAILED  test_reports_without_a_summary_wrapper_are_read
FAILED  test_github_com_is_never_malicious
FAILED  test_signed_powershell_hash_is_clean
FAILED  test_genuinely_flagged_url_still_raises_suspicion
FAILED  test_context_rows_are_preserved_for_the_analyst
FAILED  test_duplicate_taxonomies_are_collapsed
FAILED  test_high_detection_count_is_malicious
```

Restored → **168 passed**.

All three mutations were caught, by seven distinct tests. Notably
`test_github_com_is_never_malicious` — the guard written specifically for this
failure — fired. That test now has evidence behind it, not just intent.

### Earlier mutation rounds in this build

The same method was applied to every fixture-backed suite:

| Target | Mutations | Caught by |
|---|---|---|
| `alert_builder` field mapping | broke the beats-IP fallback | 1 test |
| `alert_builder` engine detection | reintroduced `ioc.source_engine` | 5 tests |
| `detection_rule_lookup` | read `engine` not `language`; skipped YAML MITRE parse | 3 tests |
| `itop_asset_lookup` | reintroduced the refetch no-op; disabled OQL validation | 8 tests |
| `thehive` case tools | `stage`→`status` trap; removed dedup; epoch-ms as seconds | 6 tests |
| **Cortex taxonomy path** | **the three above** | **7 tests** |

---

## 7. Test inventory

**9 tests — `TestGetFullAlertWithAnalysis`** (`tests/test_thehive.py`), against
the real captured Function payload:
real payload maps to alert + 4 observables · taxonomies survive into
`hive_alert` · calls the correctly-named endpoint with the right body · a
missing Function yields an actionable gap naming the reference file · a
server-side JS throw is caught via `stderr` despite HTTP 200 · an alert with no
observables returns the alert *and* a gap · empty alert id short-circuits with
no HTTP call · connection errors become gaps.

**9 tests — `TestCortexTaxonomyVerdicts`** (`tests/test_alert_builder.py`):
both report shapes read · **`github.com` is never malicious** (the regression
guard) · signed `powershell.exe` is clean · a genuinely flagged URL still raises
suspicion · context rows preserved in `details` · duplicates collapsed ·
observables with no reports produce no result · the `level` fallback still works
for ratio-less analyzers · a high detection count (`42/70`) is malicious.

Fixture: `tests/fixtures/thehive_real.json` → `function_payload`, the verbatim
response captured 2026-08-09.

---

## 8. Residual risks

| Risk | Mitigation | Owner |
|---|---|---|
| **The Function is custom JS and can vanish** — an upgrade, org rename or config wipe removes it and TI goes silent | Definition preserved in `thehive-reference/`; the tool returns a gap naming it. **Re-verify after any TheHive upgrade** | maintainer |
| Detection thresholds (1 / 5) are guesses | Documented as tunable; migrate to `scoring_config.py` at step 7 and tune over 30–60 days | step 7 |
| An analyzer emitting neither ratios nor meaningful levels | Falls back to `level`, then to `unknown` with score 0 — degrades, never crashes | — |
| Only VirusTotal has produced ratio rows here | MISP/MalwareBazaar/Shodan/Urlscan take the `level` path, which is untested against real payloads from those analyzers | re-verify when they run |
| Verdict semantics not yet consumed | `threat_intel_adjustment` is written at build step 7; until then `cortex_results` is populated but nothing scores it | step 7 |
