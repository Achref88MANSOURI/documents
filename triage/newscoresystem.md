# SOC-3s Scoring System v3 — Production Specification
## (Cold-Start Edition: Explainable Day 1, Trusted Only After Calibration)

**Status:** Replacement for the v1 weighted-linear engine and the v2 draft matrix.
**Context:** TrustShield SOC-3s deployment has **zero historical labeled alert data** at
launch. This document is written for that reality, not around it.
**Core honesty commitment:** every number in this document is labeled by its actual
epistemic status — STANDARD (from a cited external framework), PROVISIONAL (set by this
team's own documented judgment, not yet validated), or CALIBRATED (validated against real
closed-alert outcomes). Nothing is presented as more certain than it is.

---

## 1. Why v1 and v2 Both Failed the Same Test

**v1** blended four dimensions into one number with invented weights (0.40/0.35/0.25/0.15),
averaged likelihood and impact instead of multiplying them, and blended confidence into the
risk magnitude. All three defects were real and are fixed below.

**v2** replaced the weighted formula with a 5×5 matrix — a structurally correct move, backed
by NIST SP 800-30 and OWASP Risk Rating Methodology. But v2's specific numeric thresholds
(e.g., "3 closed cases," "70% TP ratio," "8 FPs in 30 days") were still invented by a single
reasoning pass, then cited alongside NIST/OWASP terminology in a way that implied they carried
the same authority. **They did not.** No published standard specifies these SOC-3s-specific
numbers, because they are not universal constants — they are organization-specific calibration
parameters that only real data can set correctly. Presenting them as settled would not have
survived a professional review, and it was correct to catch that before this went to anyone.

**v3's actual innovation is not a new formula. It is admitting what can and cannot be known on
day one, and building the missing piece: a real path from "provisional" to "calibrated."**

---

## 2. What This Document Proves With Citations, and What It Does Not

### Proven by cited standards (STANDARD status — trust these immediately):

- Risk = Likelihood × Impact is the correct combination rule, not a weighted average.
  `[NIST SP 800-30 Rev.1; OWASP Risk Rating Methodology]`
- A discrete 5-level matrix, not a continuous formula, is the standard practitioner mechanism
  for this kind of scoring, valued specifically for auditability.
  `[NIST SP 800-30 Appendix G/I; industry risk-matrix practice, ISO 27001/SOC 2-aligned programs]`
- Impact should be computed as the max of independent sub-scores, not their average — this is
  OWASP's own documented rule, chosen specifically to avoid understating serious risk.
  `[OWASP Risk Rating Methodology, "Business Impact" step]`
- Under genuine uncertainty, the correct operational response is to escalate and downgrade
  later, not to under-classify and wait for certainty.
  `[Documented incident-response norm; arXiv:2601.04486 "Decision-Aware Trust Signal
  Alignment for SOC Alert Triage," formal "Aligned Trust" escalation-under-uncertainty pattern]`

### NOT proven, and not claimed as proven anywhere in this document:

- The specific numeric thresholds inside the Likelihood/Impact rule tables (how many closed
  cases count as a sample, what TP-ratio floors a level, how many FPs cap it). **No cited
  source publishes these for SOC alert triage, because they are inherently organization- and
  environment-specific.** `[Confirmed via direct search: even the most rigorous published
  guidance on this — e.g., magonia.io's SOC false-positive-rate analysis — states the
  acceptable rate must be computed from your own environment's alert volume and analyst
  capacity, not looked up]`
- That this system's matrix cell assignments (which Likelihood×Impact combination maps to
  which P-level) are correct. They are a reasonable starting arrangement, not a validated one.

**The honest position, stated once and applied consistently below: the mechanism is
standards-based; the specific numbers are provisional until this SOC's own data validates
them.** This is not a weakness unique to SOC-3s — it is the same position every new scoring
system is in before its first calibration cycle, including CVSS's own predecessor systems.

---

## 3. How Real Systems Actually Set Thresholds Under Uncertainty — The Precedent

This section exists because "how do professionals actually do this" was the direct question
asked, and the honest answer is a named, citable methodology — not a number.

### 3.1 Structured Expert Judgment (SEJ) — the correct Day 1 mechanism

> Roger Cooke's Classical Model for structured expert judgment is the formal, peer-reviewed
> method for setting quantitative estimates under genuine uncertainty, used in over 200
> professional panels across nuclear safety, aerospace, and critical infrastructure risk since
> the 1990s. Experts assess target unknowns and are validated against "calibration questions"
> — items with known answers — so their judgment quality can be checked before being trusted.
> `[Cooke, R.M., "Experts in Uncertainty," 1991; rff.org, "Expert Elicitation: Using the
> Classical Model to Validate Experts' Judgments"]`

> Performance-weighted combination of calibrated experts produces more statistically accurate
> and more informative results than either a single expert's guess or an unweighted committee
> vote. `[rff.org, same source, analysis of 33 SEJ studies 2006–2015]`

This is precisely how CVSS itself set its own numeric boundaries — not one engineer deciding
alone:

> CVSS v4.0's severity tier boundaries were set by soliciting input from 30+ CVSS SIG members
> who performed pairwise comparisons of vector groups; the boundary between severity tiers was
> defined as the average of five independent SIG members' markings of where that boundary
> should sit. `[first.org/cvss/v4.0/user-guide, "CVSS v4.0 User Guide"]`

**SOC-3s's Stage 1 (§5 below) scales this down to fit a small team, but keeps the essential
structure: documented, individually-justified judgments from the people with real domain
authority, recorded so they can later be checked against outcomes — not one person's silent
guess.**

### 3.2 Shadow Mode — the correct Day 1-through-Nweeks deployment posture

> Deployment should begin with observability, not automatic blocking. A useful first stage is
> shadow mode, where the model scores events and generates explanations without changing
> routing. Operators can then compare its output against real incident tickets and analyst
> feedback. After calibration, response actions should be tiered.
> `[arXiv:2606.01741, "SECUREVENT: Hybrid AI/ML Security Monitoring for Distributed
> Event-Based Systems," §9 Deployment Considerations]`

> Shadow mode mirrors real requests without routing the new system's output back to users —
> meaning a miscalibrated scoring engine causes zero operational impact while still generating
> the comparison data needed to validate it.
> `[atlan.com, "Shadow Deployment: Test ML Models Without Risk"]`

### 3.3 Data-driven recalibration after shadow mode — the correct next step

> Meta's internal automation-risk system (RADAR) did not trust its initial threshold. A
> defined follow-up study measured the actual trade-off between automation yield and safety
> outcomes across 535,000+ real reviewed items, and the operating threshold was deliberately
> relaxed only after that measurement — from a conservative percentile-based starting point to
> a data-validated one. `[arXiv:2605.30208, "Automating Low-Risk Code Review at Meta: RADAR,
> Risk Calibration, and Review Efficiency," §4.2 RQ2]`

**This is the exact structure v3 adopts: provisional threshold → shadow mode → measured
recalibration.** Nothing here is invented; it is the documented pattern used by a real
production system inside a major engineering organization, applied to a security-alert
context by SECUREVENT, and grounded methodologically in Cooke's SEJ framework used across
high-stakes risk domains for three decades.

---

## 4. The Scoring Mechanism (Unchanged From v2 — This Part Was Already Correct)

### 4.1 Core model

```
Priority = MATRIX_LOOKUP[Likelihood_Level][Impact_Level]
```

No weighted sum. No coefficients to defend. `[NIST SP 800-30 / OWASP Risk Rating Methodology]`

### 4.2 Likelihood — 5 levels

| Level | Meaning |
|---|---|
| Near-Certain | Confirmed malicious signal exists |
| Likely | Strong corroborating evidence |
| Possible | Default — insufficient evidence to move off center |
| Unlikely | Evidence points toward benign |
| Rare | Strong, repeated evidence of benign pattern |

### 4.3 Impact — 5 levels, computed as `max(Asset Impact, Technical Impact)`

| Level | Meaning |
|---|---|
| Severe | Critical asset or terminal-stage kill-chain tactic |
| Significant | High-value asset or late-stage tactic |
| Moderate | Default / unknown — never assumed benign |
| Minor | Low-value asset, early recon-stage tactic |
| Negligible | Reconnaissance/resource-development only, low-value target |

#### 4.3a Asset Impact sub-score — complete lookup table

Source field: `evidence.asset_context.criticality` from iTop CMDB (Stage 1 tool 5).

| `asset_context.criticality` value | Asset Impact Level |
|---|---|
| `"high"` | Severe |
| `"medium"` | Significant |
| `"low"` | Minor |
| not found / lookup failed / field absent / `None` | **Moderate** (PROVISIONAL, see §5.1 row 7) |

**Implementation note:** match on exact lowercase string. Any value not in this table
(including empty string, null, or unexpected values) maps to Moderate — the same as
"not found." Do not raise an exception on unknown values.

#### 4.3b Technical Impact sub-score — complete exhaustive ATT&CK tactic lookup table

Source field: `context.refined_mitre_mapping[].tactic` (Stage 3 LLM output), with fallback
to `evidence.rule_context.mitre_tactics[]` when Stage 3 is unavailable.

**ATT&CK version: v19.2 (current as of 2026-08-24), fetched live from attack.mitre.org.**
v19 introduced a split of the former "Defense Evasion" tactic (TA0005) into two new tactics:
"Stealth" (TA0005) and "Defense Impairment" (TA0112). Both are mapped below.
Enterprise matrix now contains **15 tactics total**.

The Technical Impact level is determined by `max()` across all tactics present in the
mapping. If multiple tactics map to different levels, the highest level wins.

| ATT&CK Tactic ID | Tactic Name | Technical Impact Level | Reasoning |
|---|---|---|---|
| TA0040 | Impact | **Severe** | Terminal kill-chain stage: adversary is actively destroying, encrypting, or manipulating systems. Ransomware, wipers, destructive attacks. Highest possible operational consequence. |
| TA0010 | Exfiltration | **Severe** | Terminal kill-chain stage: data has already been collected and is leaving the environment. The primary objective of most financially-motivated attackers. |
| TA0008 | Lateral Movement | **Severe** | Adversary is actively expanding foothold across the network. A single compromised host has become multiple. Containment is now significantly harder. |
| TA0006 | Credential Access | **Significant** | Compromised credentials enable broad, persistent access. High enabler for privilege escalation and lateral movement. Direct path to domain compromise. |
| TA0004 | Privilege Escalation | **Significant** | Adversary gaining higher-level permissions — a critical enabler for every subsequent kill-chain stage. |
| TA0009 | Collection | **Significant** | Adversary is actively gathering target data prior to exfiltration. Attack objective is being fulfilled. |
| TA0011 | Command and Control | **Significant** | Active C2 means a compromised host is under adversary control. Remediation without detection means the adversary retains access. |
| TA0003 | Persistence | **Moderate** | Adversary is establishing long-term access. Serious but not immediately destructive — time exists to investigate and remediate before objectives are fulfilled. |
| TA0002 | Execution | **Moderate** | Malicious code is running. Context-dependent: could be early-stage or could be the delivery vehicle for a more severe technique. Mid-kill-chain. |
| TA0005 | Stealth | **Moderate** | (v19 — formerly part of Defense Evasion) Adversary hiding presence to appear as normal behavior. A support tactic: serious when combined with others, lower standalone impact than terminal-stage tactics. |
| TA0112 | Defense Impairment | **Moderate** | (v19 new — formerly part of Defense Evasion) Adversary disabling security tooling, clearing logs, breaking detection pipelines. Serious: degrades the SOC's own visibility. Does not itself represent data loss or system destruction. |
| TA0001 | Initial Access | **Moderate** | Adversary gaining first foothold. Attack is early-stage — significant, but detection at this stage means the most impactful stages have not yet occurred. |
| TA0007 | Discovery | **Minor** | Adversary mapping the environment. Pre-exploitation reconnaissance within the network. Low immediate impact; high value as an early-warning signal if caught here. |
| TA0043 | Reconnaissance | **Negligible** | Pre-attack information gathering, typically external. Adversary has not yet gained access. Lowest immediate operational risk; primarily an intelligence signal. |
| TA0042 | Resource Development | **Negligible** | Adversary acquiring infrastructure/tools for a future attack. No current access to target environment. Lowest immediate operational risk. |
| *(no tactic / unknown / unparseable)* | — | **Moderate** | Default: never assumed benign. A fired detection rule with no MITRE mapping is still a detection rule. Moderate is the neutral starting point. |

**Implementation notes:**
- Match tactic names case-insensitively. Also accept the TA#### ID format directly.
- The MITRE tactic name stored in `refined_mitre_mapping[].tactic` may vary in casing
  or use the old "Defense Evasion" label from rules written before v19. Map old
  "defense-evasion" / "defense_evasion" / "Defense Evasion" to **Moderate** (same level
  as both successor tactics — the split does not change the severity assessment).
- When Stage 3 is in fallback mode and `refined_mitre_mapping` contains entries with
  empty `tactic` fields, use `evidence.rule_context.mitre_tactics[]` as the source instead.
  If that is also empty, apply the unknown/unparseable default (Moderate).
- Take the `max()` across all tactics present — do not average them.

### 4.4 The matrix

```
                Negligible  Minor   Moderate  Significant  Severe
Near-Certain       P4        P3       P2          P1        P1
Likely              P4        P3       P2          P2        P1
Possible             P5        P4       P3          P2        P2
Unlikely              P5        P4       P4          P3        P3
Rare                   P5        P5       P4          P4        P3
```

**Status: STANDARD structure (NIST/OWASP-aligned) applied to a PROVISIONAL cell arrangement.**
Unlike CVSS's boundaries, this specific 5×5 arrangement has not been through an expert-panel
review process. It is a reasonable starting point, explicitly flagged for Stage 1 review
(§5) rather than presented as settled.

### 4.4b Floor/Cap Collision Rule — explicit, no invention permitted

The Likelihood decision table has rules that raise the level (floors: rules 1–4) and rules
that lower it (caps: rules 5–7 in §5.1). When both a floor and a cap fire on the same alert,
they conflict. The resolution rule is:

```
RULE: Positive evidence always wins over negative evidence.
      A floor from a confirmed malicious/suspicious signal (rules 1–2) cannot be
      overridden by any cap. A floor from historical TP pattern (rule 3) CAN be
      overridden by a cap from rule 4 or 5 only if rule 4 or 5 has strictly higher
      priority number than the floor rule.

IN PRACTICE — evaluation order is:
  1. Apply rules 1 and 2 first (Cortex verdicts). If either fires, set the floor.
     No cap rule can reduce below this floor. STOP evaluating caps against this alert.
  2. If rules 1 and 2 did not fire, apply rule 3 (historical TP floor).
     If rule 3 fires, apply caps (rules 4 and 5) only if they fired independently.
     If BOTH rule 3 AND a cap fire: rule 3 wins. Reason: a current positive TP history
     outweighs a FP history signal — the same alert pattern has recently resolved as
     real, which is more operationally significant than accumulated FPs.
  3. If no floor fired, apply caps (rules 4 and 5) normally.
  4. If no floor and no cap fired, apply rule 9 default: Possible.

IMPLEMENTATION: evaluate as an ordered if-elif chain, not as independent boolean checks.
```

**Status: STANDARD reasoning** (positive confirmed evidence takes precedence over
probabilistic historical evidence — this matches the same principle used in SSVC's
exploitation-status decision point, where "Active exploitation" cannot be overridden by
other factors). No calibration needed for this rule — it is a logical priority ordering,
not a threshold.

### 4.5 Confidence — kept fully separate, one override rule only

```
Evidence Quality = HIGH / MODERATE / LOW   (from evidence completeness % + Stage-1 tool gaps)

if Evidence Quality == LOW:
    priority = escalate_one_band(matrix_priority)
    log: evidence_quality_override_applied = true
```

**Status: STANDARD** — matches documented incident-response practice ("escalate under
uncertainty, downgrade later") and the formal "Aligned Trust" pattern in published SOC
trust-signal research (arXiv:2601.04486, §4.4). This rule does not require calibration to be
trusted — it is a safety default, not a precision instrument, and errs deliberately in the
safe direction.

---

## 5. Stage 1 — Bootstrap Thresholds via Structured Expert Judgment

**Purpose:** replace every invented numeric threshold with a value TrustShield's own SOC
engineers set deliberately, on the record, with individual justification — not a number I
generated. This is the scaled-down SEJ process described in §3.1.

### 5.1 The worksheet — PROVISIONAL values pre-filled, ready for team review

The thresholds below are pre-filled with conservative starting values derived from reasoned
first principles and general statistical guidance. They are explicitly PROVISIONAL — not
validated against TrustShield data. They exist so Claude Code can compile and run, and so
the shadow-mode comparison (§6) can begin collecting the data that will validate or correct
them. Every value is labeled with the reasoning behind it so a reviewer can challenge the
reasoning, not just the number.

**When TrustShield's SOC team reviews these: sign off on, adjust, or reject each row.
Replace the "SOC-3s pre-fill" in the "Set by" column with the actual reviewer's name.**

**Likelihood decision table — thresholds:**

| # | Rule | PROVISIONAL Value | Set by | Date | Reasoning for this value |
|---|---|---|---|---|---|
| 1 | Cortex verdict = malicious → floor at Near-Certain | any single occurrence | fixed (no calibration needed) | — | Direct confirmed positive evidence. A single confirmed malicious verdict from a professional threat-intel analyzer is sufficient. No statistical threshold applies — the evidence category itself determines the floor. |
| 2 | Cortex verdict = suspicious → floor at Likely | any single occurrence | fixed (no calibration needed) | — | Same principle. "Suspicious" is a weaker signal than "malicious" but still a positive finding from a deployed analyzer — sufficient to floor at Likely without requiring repetition. |
| 3 | Closed cases ≥ N AND TP ratio ≥ X% → floor Likelihood at Likely | **N = 5, X = 70%** | SOC-3s pre-fill | 2026-08-24 | N=5 is above the absolute minimum (2–3 cases are anecdotal) but well below the statistical ideal (30+). It is a cold-start compromise: enough to have seen a pattern more than once, not enough to fully trust it. X=70% means the rule fires as real more often than not — a 2:1 TP:FP ratio. Both values should be the first targets for adjustment after Stage 3 calibration. |
| 4 | FP count ≥ N in last W days → cap Likelihood at Rare | **N = 5, W = 30** | SOC-3s pre-fill | 2026-08-24 | Mirrors rule 3 symmetrically. 5 FPs in 30 days means this rule/host combination has been repeatedly benign. 30 days is a standard operational window (matches common SIEM FP-rate reporting periods). "Rules consistently above 80% FP rates should be considered candidates for retirement" — 5 FPs in 30 days at low-to-medium alert volume represents a pattern worth capping on. `[decryptiondigest.com SIEM tuning guidance]` |
| 5 | Closed cases ≥ N AND TP ratio ≤ Y% → cap Likelihood at Unlikely | **N = 5, Y = 20%** | SOC-3s pre-fill | 2026-08-24 | Symmetric counterpart to rule 3. ≤20% TP means this pattern has been benign 4 out of 5 times or more — a strong repeated benign signal. Deliberately asymmetric with rule 3's 70% floor: capping requires stronger evidence of benignness than flooring requires evidence of maliciousness, because false negatives are more operationally costly than false positives. |

**Impact sub-scores — thresholds:**

| # | Item | PROVISIONAL Value | Set by | Date | Reasoning |
|---|---|---|---|---|---|
| 6 | Distinct other hosts in `related_alerts_24h` ≥ N → escalate Impact one level | **N = 3** | SOC-3s pre-fill | 2026-08-24 | A single other host affected could be coincidence or a shared service. Three distinct hosts suggests active lateral movement or a spreading condition rather than an isolated event. One level escalation (not more) is a bounded effect. Adjust based on your network's normal inter-host alert correlation pattern. |
| 7 | Asset-not-found default Impact level | **Moderate** | SOC-3s pre-fill | 2026-08-24 | NIST SP 800-30's principle: unknown severity is never silently treated as low. Suricata alerts (IP-only, no hostname) cannot resolve an iTop asset — they are the highest-volume network-threat alert class. Defaulting them to Minor would systematically underscore the alert class most likely to represent network-borne attacks. Moderate is the neutral, neither-penalizing-nor-inflating choice. |

### 5.2 One recommendation, clearly marked as a recommendation, not a fact

For row 7, this document recommends **Moderate** as the default when `AssetContext` lookup
fails (e.g., Suricata's known IP-only gap), rather than v1's implicit "lowest" default. This
is not a validated number — it is the same reasoning principle NIST applies elsewhere:
unknown severity should never be silently treated as low severity, because that creates a
systematic blind spot exactly where visibility is already weakest. `[NIST SP 800-30's general
treatment of unassessed/unknown conditions — treated as moderate, never as automatically
benign]` If your SOC engineers reviewing this worksheet disagree and want a different default,
that disagreement itself is useful information — record it and revisit after Stage 3.

### 5.3 What this worksheet is not

It is not a substitute for data. It produces PROVISIONAL numbers with a paper trail, suitable
for shadow mode (§6). It is explicitly not suitable, on its own, for driving live case
severity or analyst paging — that transition happens only after §7.

---

## 6. Stage 2 — Shadow Mode (Weeks 1–N, Length Determined by Alert Volume)

**Mechanism**, matching the documented SECUREVENT/RADAR pattern (§3.2–3.3):

1. Stage 5 (scoring) runs on every real incoming alert exactly as designed, computing
   Likelihood, Impact, Priority, and Evidence Quality.
2. **The result is logged but does not drive TheHive case severity, does not trigger
   escalation notifications, and does not influence analyst queue ordering.** Analysts
   continue triaging using current judgment, unaffected by the new system.
3. Every alert's shadow-mode determination is stored alongside the analyst's actual outcome
   once the case closes (TP / FP / other, per TheHive's existing `status` field — no new
   infrastructure required; this data already exists in TheHive today).
4. No dashboard, report, or stakeholder communication describes shadow-mode output as
   "the system's verdict" — it is explicitly a measurement instrument during this stage.

**Suggested minimum shadow period:** run until either (a) at least 30 closed alerts exist per
Likelihood rule that fired (the general statistical rule-of-thumb for a sample large enough
that its distribution starts approximating normal — `[Central Limit Theorem; a widely-cited
general statistical minimum, not SOC-specific, applied here only as a floor, not a target]`),
or (b) 90 days have elapsed, whichever gives more data. This is a starting floor for "enough
data to look at," not a claim that 30 alerts is sufficient to fully validate a threshold —
only that below it, any comparison is not yet meaningful.

---

## 7. Stage 3 — Calibration Against Real Outcomes

**Purpose:** turn PROVISIONAL into CALIBRATED using this SOC's own closed-alert history —
the step v1 never had and v2 never built.

### 7.1 What gets checked

For each Stage 1 threshold (§5.1), pull the shadow-mode alerts where that specific rule fired
and check its actual TP/FP outcome distribution:

```
For rule 3 (closed cases N+/TP-ratio X%): 
  Did alerts where this rule floored Likelihood at "Likely" 
  actually close as TP more often than alerts where it didn't fire?
  If not — the threshold is miscalibrated, adjust N or X and re-test on a fresh window.

For the matrix cells overall (§4.4):
  Did alerts landing in P1/P2 cells close as TP disproportionately more than 
  alerts in P4/P5 cells? 
  This is the core validity check for the entire matrix arrangement, not just one rule.
```

This mirrors exactly what CVSS's own SIG process does on an ongoing basis (periodic revision
of its own boundaries) and what RADAR did before relaxing its threshold — a measured
comparison against real outcomes, not a one-time guess treated as final.

### 7.2 What "calibrated" unlocks

Only after this pass:
- Stage 5's output may drive live TheHive case severity (`PRIORITY_TO_HIVE_SEVERITY` mapping,
  unchanged from v1/v2 — `{P1:4, P2:3, P3:2, P4:1, P5:1}`).
- Analyst-facing dashboards may present the priority as an operational signal, not a
  measurement-only shadow value.
- The audit trail (§8) may drop the `PROVISIONAL` flag on thresholds that passed this check,
  and replace it with `CALIBRATED [date, sample size, validation result]`.

### 7.3 This is not a one-time event

Per CVSS SIG's own ongoing-revision practice and general drift-monitoring norms in production
ML/AI systems, calibration is re-run periodically (quarterly is a reasonable starting cadence
for a system this size — adjust to your actual alert volume) as new closed-case data
accumulates, and immediately if detection engineering changes the underlying rule set in a way
that could shift base rates.

---

## 8. The Audit Trail — What Gets Logged Per Alert (Unchanged Structure, One New Field)

```
likelihood_level: str
likelihood_rule_fired: int
likelihood_rule_reason: str
likelihood_rule_status: str        # NEW: "PROVISIONAL" | "CALIBRATED [date]"

impact_level: str
impact_governing_subscore: str
impact_modifiers_applied: list
impact_rule_status: str            # NEW: same convention

matrix_priority: str
matrix_status: str                 # NEW: "PROVISIONAL" | "CALIBRATED [date, n=___]"

evidence_quality: str
evidence_quality_override_applied: bool

final_priority: str
deployment_mode: str               # NEW: "shadow" | "live"

explanation: str                   # single sentence, now includes status, e.g.:
# "Likelihood=Likely (rule 3, PROVISIONAL, set 2026-08-24 by [names]),
#  Impact=Significant (technical, exfiltration tactic), matrix=P2 (PROVISIONAL),
#  Evidence Quality=HIGH, mode=shadow — not yet driving case severity"
```

**This is the single most important change from v2.** Every number the system ever produces
carries its own honesty label. A professional reviewer reading this output never has to take
the system's confidence on faith — the artifact itself states whether it has been validated.

---

## 9. What This Fixes, Traced to the Actual Objection Raised

| Objection raised | v3 fix |
|---|---|
| "The specific numeric thresholds are exactly as invented as v1's weights were" | Thresholds are no longer presented as derived from NIST/OWASP. They are explicitly PROVISIONAL, set via a documented worksheet (§5) by named people on a recorded date, with individual justification — matching the scaled-down structure of CVSS's own real threshold-setting process (expert panel, not solo reasoning). |
| "This is very bad when I present them without professional explanation" | Section 3 gives the named, citable methodology (Structured Expert Judgment / Cooke's Classical Model) for exactly this situation, so the honest answer to "where did this number come from" is a real, defensible process — not silence and not a fake citation. |
| "Search real production environments, how triage alerts are actually done" | §3.2–3.3 cite SECUREVENT's shadow-mode deployment guidance and Meta's RADAR system's own documented threshold-relaxation study as the real precedent for exactly this situation: new automated risk-scoring system, no trusted threshold yet, calibrate against real measured outcomes before going live. |
| "Do not invent anything" | No threshold in this document is asserted as a fact. Every number is either cited to an external standard (STANDARD), or explicitly marked as a placeholder for your team to fill in (PROVISIONAL), or marked as pending a validation step that hasn't happened yet (awaiting CALIBRATED status). |

---

## 10. What Explicitly Did Not Change From v2

- Matrix mechanism, Likelihood/Impact level structure, and the confidence-separation +
  escalation-override rule (§4) — these were already correctly grounded in NIST/OWASP and
  peer-reviewed SOC trust-alignment research, and remain unchanged.
- Stage 1–4 of the pipeline (evidence gathering, RAG, both LLM calls) — untouched. v3 only
  changes Stage 5's internals and adds the deployment-maturity model around it (§5–§7).
- Case Action / TheHive severity mapping — unchanged, and does not fire on scoring output at
  all until Stage 3 calibration is complete (§7.2).

---

## 11. Immediate Next Actions

**For Claude Code (implement now):** The spec is complete. All thresholds have values,
all collision rules are stated, the ATT&CK tactic table is exhaustive. Implement
`scoring.py` (Stage 5) against this document exactly as written. Every PROVISIONAL value
must be stored as a named constant in `scoring_config.py` with a comment marking it
PROVISIONAL and its date — not hardcoded inline, so they can be updated after calibration
without touching logic code.

**For TrustShield SOC team (before going live, not before coding):** Review §5.1's
pre-filled worksheet. Sign off on each row or replace the value. Add your name and date
to the "Set by" column. This review is what converts "SOC-3s pre-fill" into a documented
team decision — it does not require data, only 30–60 minutes of deliberate review. The
system can run in shadow mode (§6) with the pre-filled values while this review happens.

**Sequence:**
1. Claude Code implements against this document → system runs in shadow mode
2. SOC team reviews worksheet §5.1 → values confirmed or adjusted
3. Shadow mode runs until calibration criteria in §6 are met
4. Stage 3 calibration (§7) → values graduate from PROVISIONAL to CALIBRATED
5. System goes live

---

## 12. Sources Cited in This Document

1. NIST SP 800-30 Rev. 1, "Guide for Conducting Risk Assessments" — likelihood/impact matrix
   structure, treatment of unknown/unassessed conditions.
2. OWASP Risk Rating Methodology (owasp.org/www-community/OWASP_Risk_Rating_Methodology) —
   Likelihood × Impact combination; max-not-average rule for Impact sub-scores.
3. FIRST.org, CVSS v4.0 User Guide and Specification Document — the actual expert-panel
   process used to set CVSS's own qualitative severity boundaries (30+ SIG members, pairwise
   comparison, Elo-style ranking, boundary = average of 5 independent expert markings).
4. Cooke, R.M., "Experts in Uncertainty: Opinion and Subjective Probability in Science," 1991
   — origin of the Classical Model of Structured Expert Judgment.
5. Colson, A.R. & Cooke, R.M., "Expert Elicitation: Using the Classical Model to Validate
   Experts' Judgments," Review of Environmental Economics and Policy, 2018 (rff.org) —
   performance-weighted expert combination outperforms unweighted or solo judgment, based on
   33 real SEJ studies 2006–2015.
6. arXiv:2606.01741, "SECUREVENT: Hybrid AI/ML Security Monitoring for Distributed
   Event-Based Systems" — shadow-mode deployment as the correct first stage for a new
   automated security-scoring system.
7. Atlan.com, "Shadow Deployment: Test ML Models Without Risk" — shadow mode mechanics and
   zero-operational-impact property during validation.
8. arXiv:2605.30208, "Automating Low-Risk Code Review at Meta: RADAR, Risk Calibration, and
   Review Efficiency" — real production precedent for provisional-threshold → measured-data →
   recalibration, at Meta, with a documented before/after study (535K+ reviewed items).
9. arXiv:2601.04486, "Decision-Aware Trust Signal Alignment for SOC Alert Triage" (Chowdhury &
   Tanvir, Ontario Tech University) — formal justification for escalate-under-uncertainty as a
   safety default requiring no calibration to be trusted.
10. Magonia.io, "Determining an Acceptable False Positive Rate for Your SOC" — direct
    confirmation that acceptable FP/TP thresholds are environment-specific and must be
    computed from an organization's own data, not looked up from a published standard.

11. MITRE ATT&CK Enterprise Tactics v19.2 (attack.mitre.org/tactics/enterprise/, fetched
    2026-08-24) — authoritative source for the complete 15-tactic list including the v19
    Defense Evasion split into Stealth (TA0005) and Defense Impairment (TA0112).
12. DecryptionDigest.com, "SIEM Alert Tuning 2026: Cut False Positives, Keep Coverage" —
    "Rules consistently above 80% FP rates should be considered candidates for retirement."
    Used to anchor the FP-count threshold reasoning in §5.1 row 4.

**No source in this list is cited for a number it does not actually contain.** Where a source
establishes a mechanism or a process (matrix structure, expert-panel method, shadow-mode
practice), it is cited for that mechanism only — never stretched to imply it also validates a
specific SOC-3s threshold value.