# Score Review — how the SOC-3s triage service turns an alert into a number

**Scope:** everything that produces `PriorityScore` — the likelihood dimension, the impact
dimension, the confidence dimension, the LLM's contextual modifiers, the velocity multiplier,
the final weighted formula, the priority band, and the confidence gate.

**Files that matter:**

| File | Role |
|---|---|
| `scoring.py` | All the math. Pure functions, no I/O, no LLM, no `schemas` output dependency. |
| `scoring_config.py` | Every tunable number. Nothing here is load-bearing on *correctness*, only on *calibration*. |
| `config.py` (L241-253) | The four weights + the four modifier strengths, `.env`-overridable. |
| `nodes/score.py` | Stage 5's node — calls `scoring.py`, wraps the raw dict into typed `PriorityScore` / `TriageResult`. |
| `schemas/result.py` | `PriorityScore` (the audit trail), `ModifierApplied`, `TriageResult`. |

**The hard rule this whole document exists around** (CLAUDE.md): `scoring.py` is the **only**
place in the entire pipeline where a number is computed. `alert_builder.py` stays neutral.
Stage 3 and Stage 4 (the only two LLM calls in the service) emit **labels**, never scores —
with exactly one deliberate exception, `llm_criticality_score`, covered in §5.

---

## 1. Where scoring begins

Scoring is **Stage 5**. It is the 5th of 6 stages, and it runs *after* both LLM calls have
already finished. `main.py`'s `POST /triage` handler runs them in strict sequence:

```
ingest      main.py fetches the TheHive alert, alert_builder.build_canonical_alert(...)
            -> CanonicalAlert
stage 1     nodes/gather.py::gather_evidence(alert)          -> RawEvidence
stage 2     nodes/rag.py::rag_enrichment(raw_evidence)       -> EnrichedEvidence
stage 3     nodes/context.py::context_analysis(evidence)     -> ContextualAssessment   [LLM #1]
stage 4     nodes/analyze.py::analyst_verdict(ctx, ev)       -> TriageVerdict          [LLM #2]
stage 5     nodes/score.py::priority_scoring(verdict, ctx, ev) -> TriageResult  <-- SCORING
stage 6     nodes/case_action.py::case_action(...)           -> CaseActionResult
```

Stage 5 is the **only synchronous node** in the pipeline (`def`, not `async def`) — it performs
no I/O at all, so an `async def` with nothing to await would be decoration. Its budget is
<200 ms; the real live run measured 0 ms.

### What it takes as input — exactly three objects, nothing else

`priority_scoring(verdict, context, evidence)`:

1. **`evidence: EnrichedEvidence`** — everything Stage 1 gathered from the 8 backends
   (Elasticsearch, TheHive, iTop, OpenCTI, FP-tracking DB, detection-rule lookup...) plus
   Stage 2's Qdrant RAG matches, plus the original `CanonicalAlert` nested inside it.
   *This is where almost all the deterministic signal comes from.*
2. **`context: ContextualAssessment`** — Stage 3's LLM output. Contributes `contextual_modifiers`,
   `refined_mitre_mapping`, `correlation_decision.kill_chain_progression_detected`, and
   `llm_criticality_score`.
3. **`verdict: TriageVerdict`** — Stage 4's LLM output. **Contributes exactly one thing to the
   number**: `verdict.verdict` (`true_positive`/`false_positive`/`needs_review`), used only in
   the confidence dimension's consistency bonus.

Stage 5 makes **zero** calls to anything. Nothing can time out here, nothing can 404. That's
why its own `try/except` is documented as a backstop for a genuine code bug, not a normal path
(it returns a neutral P3/50 if `scoring.py` itself ever raises).

---

## 2. The shape of the whole thing

Three dimensions are computed **deterministically** from evidence. Two of them then get
**adjusted** by the LLM's contextual modifiers. All three, plus the LLM's holistic criticality
score, are combined with fixed weights, then multiplied by a velocity multiplier, then banded.

```
                     ┌──────────────── deterministic, from evidence ────────────────┐
                     │                                                              │
   base_likelihood  ─┤ rule severity + threat intel + FP penalty + rule status       │
                     │ + historical pattern                            (clamp 0-100) │
                     │                          │                                   │
                     │                          ▼  + LLM modifiers (dimension="likelihood")
                     │                   adjusted_likelihood            (clamp 0-100)│
                     │                                                              │
   base_impact      ─┤ asset criticality + MITRE tactic severity + blast radius      │
                     │ + data sensitivity                              (clamp 0-100) │
                     │                          │                                   │
                     │                          ▼  + LLM modifiers (dimension="impact")
                     │                    adjusted_impact               (clamp 0-100)│
                     │                                                              │
   base_confidence  ─┤ evidence completeness − gap penalty + verdict consistency      │
                     │ + source reliability                            (clamp 0-100) │
                     │      (NO modifiers — ContextualModifier has no                │
                     │       "confidence" dimension)                                 │
                     └──────────────────────────────────────────────────────────────┘
                                                │
   llm_criticality_score (Stage 3 LLM, 0-100) ──┤
                                                ▼
         weighted = (0.40×L + 0.35×I + 0.25×C + 0.15×K) / 1.15
                                                │
                          × velocity_multiplier (0.8 / 1.0 / 1.15 / 1.2 / 1.3)
                                                │
                                    score = round(clamp(·, 0, 100))
                                                │
                        band: >=85 P1 | >=65 P2 | >=40 P3 | >=20 P4 | else P5
                                                │
                 if adjusted_confidence < 40 -> escalate one band (confidence gate)
                                                │
                                     PriorityScore (final)
```

Note the `/ 1.15` — the weights **do not sum to 1.0** (0.40 + 0.35 + 0.25 = 1.00, plus
`WEIGHT_LLM_CRITICALITY = 0.15` = **1.15**). Dividing by the weight sum is what keeps the
result inside 0-100 when the fourth, *augmenting* component was added. `WEIGHT_LLM_CRITICALITY`
augments the original three rather than replacing any of them.

---

## 3. Likelihood — "is this real?"

`scoring._base_likelihood(evidence)` — a plain sum of five terms, then clamped to 0-100.

```python
raw = (_rule_severity_score      # the anchor, 10..90
     + _threat_intel_adjustment  # -40 .. +30
     + _fp_rate_penalty          # -40 .. 0
     + _rule_status_penalty      # -30 .. 0
     + _historical_pattern_adjustment)  # -25 .. +15
return clamp(raw, 0, 100)
```

### 3.1 `rule_severity_score` — the anchor

Reads `evidence.rule_context.level` (from the `so-detection` index lookup, Stage 1 tool 2).

| `level` | score |
|---|---|
| critical | 90 |
| high | 70 |
| medium | 45 |
| low | 25 |
| informational / info | 10 |
| *rule not found, or unknown level* | **45** (`RULE_SEVERITY_SCORE_DEFAULT`) |

The default is deliberately the same as `medium` — an unknown rule is treated as
middle-of-the-road, not as innocent and not as urgent.

### 3.2 `threat_intel_adjustment` — the Cortex read

Reads `evidence.cortex_results` (analyzer reports that arrived pre-computed on the TheHive
alert; this service never calls Cortex itself).

| Condition | adjustment |
|---|---|
| any result's `verdict` contains `"malicious"` | **+30** |
| else any contains `"suspicious"` | **+15** |
| results exist but **every** `verdict` is empty | **−40** |
| `cortex_results` is empty entirely | **0** |

This is the single most interpretive function in the file, and its docstring says so.
`CortexResult.verdict` is *pre-filtered* upstream to only malicious/suspicious taxonomy rows.
So an **empty verdict on a result that exists** means "an analyzer ran and found nothing
adverse" — real exculpatory evidence, worth −40. That is completely different from **no
`cortex_results` at all**, which means "no analyzer ran" — no data, worth 0. Collapsing those
two into one value would treat "we never checked" as "we checked and it's clean."
`alert_builder.py` deliberately refuses to make this call; `scoring.py` is where it's made.

### 3.3 `fp_rate_penalty` — learned false-positive history

Reads `evidence.fp_signal` (SQLite FP-tracking DB, Stage 1 tool 1).

```python
rule_proxy = min(1.0, signal.rule_fp_count_30d / 10)   # FP_COUNT_SATURATION_CAP
host_proxy = min(1.0, signal.host_fp_count_30d / 10)
return -40 * max(rule_proxy, host_proxy)               # FP_RATE_PENALTY_FACTOR
```

**Architecture §10 asked for a `long_term_fp_rate` that does not exist.** `FPSignal` carries two
independent 30-day **counts** (rule-scoped and host-scoped), not a rate — because
`record_triage_outcome` only ever writes a row on a *false-positive* closure, never a
true-positive one, so `fp_count / total` has no valid denominator. Redesigned as a **saturating
pseudo-rate**: 10 FPs in 30 days saturates the proxy at 1.0, giving the full −40.

`max()`, not sum or average, of the two proxies — either signal alone at full strength is
meaningful. A rule that's a known problem on one specific host would be under-penalized by an
average, and a sum would double-count the same underlying incident.

### 3.4 `rule_status_penalty` — the day-one FP signal

Reads `evidence.rule_context.status` (the Sigma rule's own maturity field).

| `status` | penalty |
|---|---|
| stable | 0 |
| test | **−10** |
| experimental | **−20** |
| deprecated / unsupported | **−30** |
| *missing* | 0 |

The point of this term: `fp_rate_penalty` needs weeks of accumulated history before it says
anything. `rule_status_penalty` works on the very first alert the service ever sees, because the
rule author already told us the rule is unproven.

### 3.5 `historical_pattern_adjustment` — closed-case outcomes

Reads `evidence.closed_cases_summary` (TheHive closed cases matching this rule/entities).

```python
sample = tp_count + fp_count
if sample < 3:  return 0.0          # HISTORICAL_MIN_SAMPLE
tp_ratio = tp_count / sample
return -25 + tp_ratio * (15 - (-25))   # linear: -25 at 0% TP .. +15 at 100% TP
```

Below 3 closed cases the term is silent — one prior case is not a pattern. Note `other_count`
(Duplicated / Indeterminate / closed with no resolution) is deliberately **not** in the
denominator: a high "other" count means the historical signal is *weak*, which is a different
thing from it being *negative*.

---

## 4. Impact — "if it's real, how bad?"

`scoring._base_impact(context, evidence)` — a sum of four terms, clamped to 0-100.

```python
raw = (_asset_criticality_score      # 20..95
     + _mitre_technique_severity     # 15..100
     + _blast_radius_score           # 0..20
     + _data_sensitivity_bonus)      # 0..25
return clamp(raw, 0, 100)
```

This is the dimension that **saturates most easily** — asset 95 + MITRE 65 already equals 160,
clamped straight to 100. In the real live run below, `base_impact` was 100 and the LLM's +15
impact modifier changed nothing at all, because it was already at ceiling.

### 4.1 `asset_criticality_score`

Reads `evidence.asset_context.criticality` (iTop CMDB lookup, Stage 1).

| `criticality` | score |
|---|---|
| high | 95 |
| medium | 60 |
| low | 35 |
| *asset not found, or blank* | **20** (`ASSET_CRITICALITY_SCORE_DEFAULT`) |

**Known structural limitation:** `itop_asset_lookup` is hostname/asset-number keyed only — IP is
not a usable lookup key on this iTop instance. A Suricata-shaped alert has no hostname at all,
only IPs, so it will *always* land on the 20 default here. That's not a bug that gets fixed by
populating iTop; it needs an IP-to-asset resolution step that doesn't exist.

### 4.2 `mitre_technique_severity` — kill-chain position, not technique priority

```python
tactics = [m.tactic for m in context.refined_mitre_mapping if m.tactic]
if not tactics:
    tactics = evidence.rule_context.mitre_tactics    # <-- the fallback that matters
if not tactics:
    return 30                                        # MITRE_TACTIC_SEVERITY_DEFAULT
return max(MITRE_TACTIC_SEVERITY.get(t.lower(), 30) for t in tactics)
```

**Architecture §10 asked for `technique.priority_0_5`, which does not exist** on any of the 697
real MITRE technique points in this deployment's Qdrant collection (live-verified). So severity
is derived from the **ATT&CK tactic** instead — kill-chain position — the one MITRE dimension
every real source in this repo actually carries.

| tactic | severity | | tactic | severity |
|---|---|---|---|---|
| impact | 100 | | persistence | 60 |
| exfiltration | 90 | | execution | 55 |
| lateral-movement | 80 | | defense-evasion | 55 |
| credential-access | 75 | | initial-access | 50 |
| privilege-escalation | 70 | | discovery | 30 |
| collection | 70 | | reconnaissance | 15 |
| command-and-control | 65 | | resource-development | 15 |
| | | | *unknown* | **30** |

`max()`, not average — one exfiltration technique in a chain of five discovery techniques is an
exfiltration alert.

**The fallback branch is load-bearing and mutation-tested.** When Stage 3's LLM is down,
`nodes/context.py::_stage_3_fallback` builds `refined_mitre_mapping` entries with
`tactic=""` on every one. Without the fallback to `rule_context.mitre_tactics`, a downed LLM
would silently collapse this term to the 30 default — **which is exactly the v3
"silent-severity-cap" bug architecture §8 calls out by name**. Deleting the fallback branch
turns a test red.

### 4.3 `blast_radius_score` — lateral spread

```python
this_host  = evidence.canonical_alert.host.hostname
other_hosts = {a.host for a in evidence.related_alerts_24h if a.host and a.host != this_host}
return min(20, len(other_hosts) * 5)     # BLAST_RADIUS_PER_HOST / _CAP
```

5 points per *distinct other host* seen in the 24h related-alert window, capped at 20. The
alert's own host is excluded — it isn't part of the spread, it's the origin.

### 4.4 `data_sensitivity_bonus`

`min(25, len(asset_context.data_sensitivity) * 5)` — 5 points per sensitivity tag on the iTop
asset record (PII, PCI, regulated, etc.), capped at 25.

---

## 5. Confidence — "how much do we trust the above?"

`scoring._base_confidence(verdict, evidence, base_likelihood)`:

```python
gap_count = len(evidence.investigation_gaps)
raw = (_evidence_completeness_pct        # 0..100
     - gap_count * 10                    # GAP_PENALTY_PER_GAP
     + _verdict_consistency_bonus        # 0 or 20
     + _source_reliability_bonus)        # 0 or 15
return clamp(raw, 0, 100), gap_count
```

Confidence is **not** a confidence *in the verdict* — it's a confidence in the *evidence base*.
It's the term that decides whether the confidence gate fires (§8).

### 5.1 `evidence_completeness_pct` vs `gap_count` — deliberately two different signals

Architecture §10 lists both, and they are **not** the same thing. Computing both from one signal
would double-penalize the same fact under two names.

- **`evidence_completeness_pct`** measures how much `CanonicalAlert` extraction pulled *out of
  the alert itself*: 8 boolean checks, `100 * sum / 8`.

  ```
  host is not None | user is not None | process is not None | network is not None
  file is not None | any external_ip/domain/url | hashes not empty | cortex_results non-empty
  ```
  An `assert len(checks) == EVIDENCE_COMPLETENESS_FIELD_COUNT` guards the constant against drift.

- **`gap_count`** measures how many Stage 1 **tool calls** produced a `Gap` (a backend timed out,
  401'd, returned nothing usable). Each gap costs a flat 10 points.

One is "how rich was the alert"; the other is "how many of our 8 backends failed us."

### 5.2 `verdict_consistency_bonus` — the only place Stage 4's verdict touches the number

```python
predicted_positive = base_likelihood > 50    # DETERMINISTIC_LIKELIHOOD_POSITIVE_THRESHOLD
if predicted_positive     and verdict.verdict == "true_positive":  return 20
if not predicted_positive and verdict.verdict == "false_positive": return 20
return 0
```

**+20 when the LLM and the deterministic math independently agree.** Two independent methods
reaching the same conclusion is genuine evidence that the conclusion is trustworthy. Note
`needs_review` never earns this bonus — the LLM declining to call it is not agreement.

### 5.3 `source_reliability_bonus`

+15 when `rule_context.source_engine == "sigma"` **and** the rule carries MITRE ATT&CK mappings.
A well-maintained, MITRE-tagged Sigma rule is a more trustworthy signal than an untagged one.

---

## 6. The LLM's contextual modifiers — bounded influence

This is the "hybrid" half of "hybrid priority scoring." Stage 3's LLM cannot output a score. It
outputs `ContextualModifier` entries:

```python
dimension:   Literal["likelihood", "impact"]     # note: NO "confidence"
factor_name: str                                  # e.g. "false_positive_history"
direction:   Literal["increase", "decrease"]
strength:    Literal["weak", "medium", "strong", "critical"]
reasoning:   str
```

The prompt frames these as *"factors the deterministic scoring formula cannot see"* — the LLM's
job is to catch what the tables in §3 and §4 structurally can't.

`scoring.apply_llm_modifiers(base, modifiers, dimension)` converts them:

```python
for m in modifiers:
    if m.dimension != dimension: continue
    magnitude = MODIFIER_STRENGTHS[m.strength]         # weak 5, medium 10, strong 15, critical 25
    magnitude = min(magnitude, MODIFIER_MAX_SINGLE)    # 25 — per-modifier cap
    signed    = +magnitude if m.direction == "increase" else -magnitude
    total    += signed

total    = clamp(total, -30, +30)      # MODIFIER_MAX_TOTAL_PER_DIMENSION — per-dimension cap
adjusted = clamp(base + total, 0, 100)
```

### The two caps are the guardrail, and they're the whole point

| Cap | Value | What it stops |
|---|---|---|
| `MODIFIER_MAX_SINGLE` | ±25 | Any one claimed factor from dominating a dimension. |
| `MODIFIER_MAX_TOTAL_PER_DIMENSION` | ±30 | **Twenty** modifiers from stacking to ±500. |

These apply **regardless of how many modifiers Stage 3 emitted or how strong each claims to be**.
This is the prompt-injection and overconfident-LLM guard: an attacker who gets text into a log
line that Stage 3 reads, and successfully talks the model into emitting ten "critical/increase"
modifiers, moves the dimension by **30 points, not 250**. The LLM adjusts the score; it can never
*set* it.

**Confidence takes no modifiers at all** — `ContextualModifier.dimension` has no `"confidence"`
value, so `adjusted_confidence = base_confidence`, always. The LLM cannot talk its way out of
the confidence gate.

### The one LLM number: `llm_criticality_score`

The single deliberate exception to "the LLM never emits a number." Stage 3 outputs a holistic
0-100 `llm_criticality_score`, which enters the final formula as the fourth weighted component at
weight **0.15** (vs 0.40/0.35/0.25 for the deterministic three). The prompt gives it calibration
bands (0-20 almost certainly benign ... 81-100 highly critical) and explicitly instructs the model
to reconcile it against its own modifiers and correlation decision before answering. On the Stage
3 fallback path it stays at its neutral default of **50** — a downed LLM must never fabricate a
criticality judgment it never made.

---

## 7. Velocity multiplier — urgency, not severity

`scoring._velocity_multiplier(context, evidence)`. **First match wins**, in this order:

| # | Condition | Multiplier |
|---|---|---|
| 1 | more than 5 related alerts in the last **1 hour** | **1.30** — active alert cluster |
| 2 | `context.correlation_decision.kill_chain_progression_detected` | **1.20** |
| 3 | `closed_cases_summary.tp_count > 0` | **1.15** — this pattern has been real before |
| 4 | alert older than **24 h** | **0.80** — stale evidence |
| — | none of the above | **1.00** |

This is the only multiplicative term in the whole system; everything else is additive. It's what
separates "bad" from "bad *and happening right now*."

Two documented approximations here:

- **`recent_similar_tp`** — architecture names it, but `ClosedCasesSummary` carries **no recency
  field at all**, only counts. Approximated as `tp_count > 0`: real TP history, but not
  verifiably *recent* history. Tighten this if `ClosedCasesSummary` ever grows a recency field.
- **`evidence_age_hours`** — architecture §10 never said *which* timestamp it meant, and the alert's
  `@timestamp` and the underlying triggering event's timestamp can differ by days
  (SESSION-FINDINGS.md §4.5.6, open until Stage 5 was built). **Resolved to
  `CanonicalAlert.timestamp`** — the Security Onion alert's own detection time, i.e. *how old the
  investigation is*, not how old the triggering event was. For a staleness gate, "how long has
  this been sitting unhandled" is the question that matters.

`_related_alerts_1h` filters `related_alerts_24h` down to the last hour itself, tz-normalising
naive timestamps to UTC as it goes.

---

## 8. The final formula, the bands, and the gate

```python
weight_sum = 0.40 + 0.35 + 0.25 + 0.15                  # = 1.15
weighted   = (0.40*adjusted_likelihood
            + 0.35*adjusted_impact
            + 0.25*adjusted_confidence
            + 0.15*llm_criticality_score) / weight_sum
score      = round(clamp(weighted * velocity, 0, 100))
```

### Bands

| Score | Priority |
|---|---|
| >= 85 | **P1** |
| >= 65 | **P2** |
| >= 40 | **P3** |
| >= 20 | **P4** |
| else | **P5** |

Checked top-down in `PRIORITY_BANDS` order; first threshold met wins.

### The confidence gate — the counter-intuitive one

```python
confidence_gate_applied = adjusted_confidence < 40      # CONFIDENCE_GATE_THRESHOLD
if confidence_gate_applied:
    priority = _escalate_priority(priority)             # one band MORE severe, floors at P1
```

**Low confidence makes the alert *more* urgent, not less.** This is intentional and it is the
most important design decision in the scoring system. The reasoning: a low-confidence result
means the pipeline could not gather enough evidence to be sure — backends timed out, the alert
was thin, the LLM and the math disagreed. An alert we *don't understand* is exactly the alert
that most needs a human to look at it. Burying it deeper in the queue because the automation
was uncertain would be the wrong failure direction for a security tool.

The gate is band-level, not score-level: the numeric `score` is unchanged, only `priority` moves.
So a `PriorityScore` where `score=69` and `priority="P1"` is not a bug — it's the gate having
fired, and `confidence_gate_applied: true` in the same object records that it did.

### Where the priority goes next

Stage 6 (`nodes/case_action.py`) maps it onto TheHive's severity scale via
`PRIORITY_TO_HIVE_SEVERITY = {P1: 4, P2: 3, P3: 2, P4: 1, P5: 1}`, and writes it into the case
title, description and tags.

---

## 9. A real worked example

From `tests/fixtures/score_live_run_real.json` — a genuine live run against real backends
(the xordump / `Invoke-WebRequest` alert), every intermediate value hand-verified before the
test suite was written.

**Likelihood:**
```
rule_severity_score            70    (rule level = high)
threat_intel_adjustment         0    (no cortex_results)
fp_rate_penalty                -0    (no FP history yet)
rule_status_penalty           -10    (rule status = test)
historical_pattern_adjustment   0    (fewer than 3 closed cases)
                             ────
base_likelihood                60
LLM modifier: false_positive_history / decrease / medium   -10
                             ────
adjusted_likelihood            50
```

**Impact:**
```
asset_criticality_score        95    (iTop criticality = high)
mitre_technique_severity       65    (max of execution 55, command-and-control 65)
blast_radius_score              0
data_sensitivity_bonus          0
                             ────
raw 160 -> clamped            100
LLM modifier: persistence_indicators / increase / strong   +15
                             ────
adjusted_impact               100    (already at ceiling — the +15 changed nothing)
```

**Confidence:**
```
evidence_completeness_pct      50    (4 of 8 alert fields populated)
gap_count 4 x -10             -40    (4 Stage-1 backends produced Gaps)
verdict_consistency_bonus       0    (verdict was needs_review — never earns it)
source_reliability_bonus      +15    (sigma engine + MITRE tags)
                             ────
base_confidence                25
```

**Final:**
```
(0.40x50 + 0.35x100 + 0.25x25 + 0.15x50) / 1.15 x 1.15 = 69

velocity 1.15  (closed_cases_summary.tp_count > 0)
score    69    -> band P2
confidence 25 < 40 -> gate fires -> escalated to P1
```

Read that last step carefully — it's the system working exactly as designed. A merely-P2 score,
escalated to P1 because the pipeline only managed to gather half the alert's fields and lost four
backends to gaps. The service is saying *"I don't have enough to be sure about this one — put it
in front of a human."*

---

## 10. The audit trail

`PriorityScore` is deliberately verbose. Every intermediate value is preserved so an analyst
disputing a priority can trace exactly which term drove it, without re-running anything:

```
score, priority
base_likelihood, adjusted_likelihood, likelihood_modifiers_applied[{factor, adjustment}]
base_impact,     adjusted_impact,     impact_modifiers_applied[{factor, adjustment}]
base_confidence, confidence_gate_applied
velocity_multiplier, llm_criticality_score
final_score_calculation      <- the formula rendered as a human-readable string
components{}                 <- every single named sub-term from section 3/4/5
```

`components` is an open `dict[str, float]` rather than ~16 typed fields, because those sub-terms
are `scoring_config.py` tunables, not architecture-fixed contract fields — `scoring.py` alone
decides which keys land there.

---

## 11. Things worth knowing before you tune it

1. **Everything in `scoring_config.py` is a guess awaiting calibration.** Architecture §17 is
   explicit that the weights and modifier strengths are educated guesses expecting 30-60 days of
   tuning against real analyst feedback. Nothing there is load-bearing on *correctness*; it is
   load-bearing on *calibration*. The weights and modifier strengths are additionally
   `.env`-overridable through `config.py`.

2. **Stage 4's `likelihood` and `impact_if_true` labels do not feed the score.** `TriageVerdict`
   carries `likelihood: unlikely|possible|likely|near_certain` and
   `impact_if_true: minor|moderate|significant|severe` — and `scoring.py` reads **neither**.
   Grep it: the only `verdict.*` access in the whole file is `verdict.verdict`, twice, in
   `_verdict_consistency_bonus`. Those labels are carried through to `TriageResult` for the
   analyst to read, but the numeric likelihood and impact dimensions are computed entirely from
   evidence + Stage 3's modifiers. This is easy to get wrong when reading the code casually.

3. **Impact saturates fast.** A high-criticality asset (95) plus almost any serious tactic
   already clears 100. When `base_impact` is at ceiling, impact modifiers are inert — as the real
   run above demonstrates. If impact discrimination matters for your queue, that's the first
   thing to retune.

4. **Three architecture §10 terms were redesigned because the data doesn't exist**, each
   documented at its redesign site rather than silently ported: `long_term_fp_rate` (§3.3),
   `technique.priority_0_5` (§4.2), and `evidence_age_hours`' timestamp ambiguity (§7).

5. **Test coverage:** 93 tests in `tests/test_scoring.py`. Four guards were mutation-tested — the
   per-dimension modifier cap, the MITRE-tactic fallback, the confidence-gate escalation, and the
   priority-band boundary comparison. The confidence-gate mutation **survived on the first pass**,
   because the test only asserted the boolean flag and not that escalation actually changed the
   band; the test was fixed to assert `result["priority"] == _escalate_priority(unescalated)`, the
   mutation re-run and confirmed red, then restored. That's left in the test's own docstring as a
   live example of why this repo's fixture discipline exists.
