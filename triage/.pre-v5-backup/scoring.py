"""Stage 5 — SOC-3s Scoring System **v3** (`newscoresystem.md`). Pure Python,
no I/O, no LLM. `CLAUDE.md`'s hard constraint still holds and is now easier to
hold: this is the ONLY place in the pipeline a priority is computed.

**What changed from v1, and why** (`newscoresystem.md` §1):

| v1 | v3 |
|---|---|
| One 0-100 number from a weighted sum with invented weights (0.40/0.35/0.25/0.15) | A discrete 5x5 matrix lookup — no coefficients to defend `[NIST SP 800-30, OWASP]` |
| Likelihood and impact AVERAGED into the same number | Likelihood x Impact, the standard combination rule |
| Impact sub-scores SUMMED (asset + tactic + blast radius + sensitivity) | `max(asset, technical)` — OWASP's own documented rule, chosen specifically to avoid understating serious risk |
| Confidence blended into the risk magnitude as a third weighted term | Confidence kept fully separate; one escalate-only override |
| LLM modifiers moved the number by up to ±30 | Not referenced by any rule — see below |

**Deliberately unused by v3's scoring**: Stage 3's `contextual_modifiers` and
`llm_criticality_score`, and Stage 4's `likelihood`/`impact_if_true` labels.
v3's decision table (`newscoresystem.md` §4.2-§4.3, §5.1) is exhaustive and
names none of them. They stay in `/triage`'s response and the TheHive case
write-up as analyst-facing context — they no longer move the priority.
User-confirmed 2026-08-24. This module's `compute_priority` does not even take
`TriageVerdict` as a parameter any more; `nodes/score.py` still receives it, for
`TriageResult`'s other fields.

**Every threshold lives in `scoring_config.py`**, never inline here, per
`newscoresystem.md` §11 — so §7's calibration pass can update a PROVISIONAL
value without touching a line of logic.

Public API, mirroring the audit trail `newscoresystem.md` §8 requires:
`assess_likelihood`, `assess_impact`, `assess_evidence_quality`,
`compute_priority`. Each returns a plain `dict`; `nodes/score.py` wraps the
last into the typed `PriorityScore`, keeping this module free of a `schemas`
dependency on its own output type (only on the input types it reads).
"""

from __future__ import annotations

import scoring_config as cfg
from schemas import ContextualAssessment, EnrichedEvidence


# ---------------------------------------------------------------------------
# Level algebra — every escalation and every max() in v3 works on the ordered
# index, never on the string, so a level can never be silently invented.
# ---------------------------------------------------------------------------


def _level_index(level: str, scale: list[str]) -> int:
    """Position of `level` on `scale` (ascending). Unknown strings resolve to
    the scale's midpoint rather than raising — the same never-raise posture
    every other stage in this pipeline holds, and the same "unknown is never
    silently benign" principle `newscoresystem.md` §4.3a applies to asset
    criticality."""
    try:
        return scale.index(level)
    except ValueError:
        return len(scale) // 2


def _max_level(a: str, b: str, scale: list[str]) -> str:
    return a if _level_index(a, scale) >= _level_index(b, scale) else b


def _escalate_level(level: str, scale: list[str]) -> str:
    """One level more severe, saturating at the top of the scale."""
    return scale[min(len(scale) - 1, _level_index(level, scale) + 1)]


def escalate_one_band(priority: str) -> str:
    """One priority band more severe, saturating at P1.
    `newscoresystem.md` §4.5's `escalate_one_band`."""
    order = cfg.PRIORITY_BANDS_ORDERED  # P1 first — more severe is a LOWER index
    try:
        idx = order.index(priority)
    except ValueError:
        return priority
    return order[max(0, idx - 1)]


def _normalise_tactic(tactic: str) -> str:
    """`newscoresystem.md` §4.3b implementation note: match case-insensitively
    and accept the TA#### id form directly. Underscores and spaces both fold to
    the hyphen ATT&CK's own shortnames use, so every real producer in this repo
    lands on the same key — Sigma's already-hyphenated
    `rule_context.mitre_tactics`, `tools/detection_rules.py`'s Suricata
    normalisation (`Defense_Evasion` -> `defense-evasion`), and Stage 3's
    free-form LLM output (`"Defense Evasion"`, `"TA0005"`)."""
    return tactic.strip().lower().replace("_", "-").replace(" ", "-")


# ---------------------------------------------------------------------------
# LIKELIHOOD — newscoresystem.md §5.1 rules 1-5 + §4.4b's collision rule
# ---------------------------------------------------------------------------


def _tp_ratio(evidence: EnrichedEvidence) -> tuple[int, float]:
    """`(closed_sample, tp_ratio)`. The sample is tp+fp only — `other_count`
    (Duplicated / Indeterminate / closed with no resolution) is deliberately
    excluded, as it already is in `ClosedCasesSummary`'s own docstring: a high
    "other" count means the historical signal is WEAK, which is a different
    thing from it being negative, and folding it into either side would
    misstate the ratio in whichever direction it happened to land."""
    summary = evidence.closed_cases_summary
    sample = summary.tp_count + summary.fp_count
    if sample == 0:
        return 0, 0.0
    return sample, summary.tp_count / sample


def assess_likelihood(evidence: EnrichedEvidence) -> dict:
    """`newscoresystem.md` §4.4b, implemented exactly as that section mandates:
    **an ordered if-elif chain, not independent boolean checks.**

    The ordering IS the collision rule. Positive confirmed evidence always wins
    over negative historical evidence, so once a floor fires no cap is even
    evaluated — matching SSVC's own exploitation-status precedence, where
    "Active exploitation" cannot be overridden by other decision points. §4.4b
    calls this STANDARD reasoning needing no calibration: it is a logical
    priority ordering, not a threshold.

    Evaluation order — rules 1, 2 (Cortex floors, FIXED), 3 (historical TP
    floor, PROVISIONAL), 4, 5 (caps, PROVISIONAL), 9 (default).

    Two orderings inside that chain are worth naming, because neither is
    arbitrary and neither is stated outright in §5.1's table:

    - **Rule 3 before rules 4/5.** §4.4b step 2 is explicit: when rule 3 and a
      cap both fire, rule 3 wins — a current positive TP history outweighs an
      FP history signal, because the same pattern has recently resolved as
      real.
    - **Rule 4 before rule 5.** Both are caps and both can fire on the same
      alert. Table order puts 4 first, and it is also the stronger cap (Rare vs
      Unlikely), so the chain lands on the more benign of the two rather than
      on whichever happened to be checked first.

    `newscoresystem.md` §4.4b's own prose header says "floors: rules 1-4" and
    "caps: rules 5-7", which contradicts both its own IN PRACTICE block and
    §5.1's worksheet (floors 1-3, caps 4-5). The IN PRACTICE block and the
    worksheet agree with each other, so they win; the header is a drafting slip.
    """
    cortex_results = evidence.canonical_alert.cortex_results

    # --- Rule 1 — FIXED. Direct confirmed positive evidence. ---
    if any("malicious" in r.verdict for r in cortex_results):
        analyzers = sorted({r.analyzer for r in cortex_results if "malicious" in r.verdict})
        return _likelihood_result(
            cfg.RULE_1_MALICIOUS_FLOOR,
            1,
            f"Cortex verdict 'malicious' from {', '.join(analyzers) or 'an analyzer'} "
            f"— floored at {cfg.RULE_1_MALICIOUS_FLOOR}",
            cfg.STATUS_FIXED,
        )

    # --- Rule 2 — FIXED. Weaker but still a positive analyzer finding. ---
    if any("suspicious" in r.verdict for r in cortex_results):
        analyzers = sorted({r.analyzer for r in cortex_results if "suspicious" in r.verdict})
        return _likelihood_result(
            cfg.RULE_2_SUSPICIOUS_FLOOR,
            2,
            f"Cortex verdict 'suspicious' from {', '.join(analyzers) or 'an analyzer'} "
            f"— floored at {cfg.RULE_2_SUSPICIOUS_FLOOR}",
            cfg.STATUS_FIXED,
        )

    sample, tp_ratio = _tp_ratio(evidence)

    # --- Rule 3 — PROVISIONAL. Historical TP floor. Beats any cap. ---
    if (
        sample >= cfg.RULE_3_TP_FLOOR_MIN_CLOSED_CASES
        and tp_ratio >= cfg.RULE_3_TP_FLOOR_MIN_TP_RATIO
    ):
        return _likelihood_result(
            cfg.RULE_3_TP_FLOOR_LEVEL,
            3,
            f"{sample} closed cases with a {tp_ratio:.0%} true-positive ratio "
            f"(>= {cfg.RULE_3_TP_FLOOR_MIN_CLOSED_CASES} cases, "
            f">= {cfg.RULE_3_TP_FLOOR_MIN_TP_RATIO:.0%}) — floored at "
            f"{cfg.RULE_3_TP_FLOOR_LEVEL}",
            cfg.LIKELIHOOD_RULE_STATUS,
        )

    # --- Rule 4 — PROVISIONAL. Repeated-FP cap. ---
    fp_signal = evidence.fp_signal
    if fp_signal is not None:
        fp_count = max(fp_signal.rule_fp_count_30d, fp_signal.host_fp_count_30d)
        if fp_count >= cfg.RULE_4_FP_CAP_MIN_COUNT:
            scope = (
                "rule"
                if fp_signal.rule_fp_count_30d >= fp_signal.host_fp_count_30d
                else "host"
            )
            return _likelihood_result(
                cfg.RULE_4_FP_CAP_LEVEL,
                4,
                f"{fp_count} false positives on this {scope} in the last "
                f"{cfg.RULE_4_FP_CAP_WINDOW_DAYS} days "
                f"(>= {cfg.RULE_4_FP_CAP_MIN_COUNT}) — capped at "
                f"{cfg.RULE_4_FP_CAP_LEVEL}",
                cfg.LIKELIHOOD_RULE_STATUS,
            )

    # --- Rule 5 — PROVISIONAL. Historical benign-pattern cap. ---
    if (
        sample >= cfg.RULE_5_FP_RATIO_CAP_MIN_CLOSED_CASES
        and tp_ratio <= cfg.RULE_5_FP_RATIO_CAP_MAX_TP_RATIO
    ):
        return _likelihood_result(
            cfg.RULE_5_FP_RATIO_CAP_LEVEL,
            5,
            f"{sample} closed cases with only a {tp_ratio:.0%} true-positive ratio "
            f"(<= {cfg.RULE_5_FP_RATIO_CAP_MAX_TP_RATIO:.0%}) — capped at "
            f"{cfg.RULE_5_FP_RATIO_CAP_LEVEL}",
            cfg.LIKELIHOOD_RULE_STATUS,
        )

    # --- Rule 9 — the default. Never "benign by absence of evidence". ---
    return _likelihood_result(
        cfg.RULE_9_DEFAULT_LEVEL,
        9,
        f"No floor or cap rule fired — default {cfg.RULE_9_DEFAULT_LEVEL} "
        f"({cfg.LIKELIHOOD_LEVEL_MEANING[cfg.RULE_9_DEFAULT_LEVEL]})",
        cfg.LIKELIHOOD_RULE_STATUS,
    )


def _likelihood_result(level: str, rule: int, reason: str, status: str) -> dict:
    return {
        "likelihood_level": level,
        "likelihood_rule_fired": rule,
        "likelihood_rule_reason": reason,
        "likelihood_rule_status": status,
    }


# ---------------------------------------------------------------------------
# IMPACT — newscoresystem.md §4.3, sub-scores combined with max(), then §5.1
# rule 6's bounded one-level blast-radius escalation
# ---------------------------------------------------------------------------


def _asset_impact(evidence: EnrichedEvidence) -> tuple[str, str]:
    """`(level, reason)`. §4.3a: exact lowercase match; anything else —
    including a failed lookup, a blank field, or an unexpected value — falls to
    Moderate, and NEVER raises."""
    asset = evidence.asset_context
    if asset is None or not asset.found or not asset.criticality:
        return (
            cfg.ASSET_IMPACT_DEFAULT,
            "asset not found or criticality unset — defaulted to "
            f"{cfg.ASSET_IMPACT_DEFAULT} (unknown is never treated as benign)",
        )
    criticality = asset.criticality.strip().lower()
    level = cfg.ASSET_CRITICALITY_TO_IMPACT.get(criticality)
    if level is None:
        return (
            cfg.ASSET_IMPACT_DEFAULT,
            f"unrecognised asset criticality {asset.criticality!r} — defaulted to "
            f"{cfg.ASSET_IMPACT_DEFAULT}",
        )
    return level, f"asset criticality {criticality} -> {level}"


def _technical_impact(context: ContextualAssessment, evidence: EnrichedEvidence) -> tuple[str, str]:
    """`(level, reason)`. §4.3b: `max()` across every tactic present, never an
    average.

    Source precedence is Stage 3's refined mapping, then Stage 1's
    rule-derived tactics. That fallback is load-bearing, not defensive
    decoration: `nodes/context.py::_stage_3_fallback` builds
    `refined_mitre_mapping` with `tactic=""` on every entry, so without it a
    downed Stage 3 LLM would silently collapse this sub-score to the Moderate
    default — the same class of silent severity cap architecture §8 calls out
    by name, and the reason §4.3b's implementation note spells this fallback
    out explicitly."""
    tactics = [m.tactic for m in context.refined_mitre_mapping if m.tactic and m.tactic.strip()]
    source = "Stage 3 refined MITRE mapping"

    if not tactics:
        rule_context = evidence.rule_context
        tactics = [t for t in (rule_context.mitre_tactics if rule_context else []) if t.strip()]
        source = "rule_context.mitre_tactics (Stage 3 mapping carried no tactic)"

    if not tactics:
        return (
            cfg.TACTIC_IMPACT_DEFAULT,
            f"no ATT&CK tactic available — defaulted to {cfg.TACTIC_IMPACT_DEFAULT} "
            "(a fired rule with no MITRE mapping is still a fired rule)",
        )

    level: str | None = None
    governing = tactics[0]
    for tactic in tactics:
        candidate = cfg.TACTIC_TO_IMPACT.get(_normalise_tactic(tactic), cfg.TACTIC_IMPACT_DEFAULT)
        if level is None or _level_index(candidate, cfg.IMPACT_LEVELS) > _level_index(
            level, cfg.IMPACT_LEVELS
        ):
            level, governing = candidate, tactic

    return level, f"ATT&CK tactic {governing} -> {level} (max over {len(tactics)}, from {source})"


def _other_host_count(evidence: EnrichedEvidence) -> int:
    """Distinct hosts in the 24h related-alert window that are NOT this alert's
    own host. The alert's own host is excluded because it is the origin, not
    evidence of spread."""
    this_host = evidence.canonical_alert.host.hostname if evidence.canonical_alert.host else None
    return len({a.host for a in evidence.related_alerts_24h if a.host and a.host != this_host})


def assess_impact(context: ContextualAssessment, evidence: EnrichedEvidence) -> dict:
    """`newscoresystem.md` §4.3 — `max(Asset Impact, Technical Impact)`, then
    §5.1 rule 6's blast-radius escalation.

    `max()`, never an average, is OWASP Risk Rating Methodology's own
    documented rule for combining impact sub-scores, chosen specifically to
    avoid understating serious risk: a low-value host running a ransomware
    encryption technique is a Severe event, and averaging it against the
    asset's Minor rating would hide that.
    """
    asset_level, asset_reason = _asset_impact(evidence)
    technical_level, technical_reason = _technical_impact(context, evidence)

    base_level = _max_level(asset_level, technical_level, cfg.IMPACT_LEVELS)
    if asset_level == technical_level:
        governing = "both"
    elif base_level == asset_level:
        governing = "asset"
    else:
        governing = "technical"

    modifiers: list[str] = []
    level = base_level
    other_hosts = _other_host_count(evidence)
    if other_hosts >= cfg.RULE_6_BLAST_RADIUS_MIN_OTHER_HOSTS:
        escalated = _escalate_level(level, cfg.IMPACT_LEVELS)
        modifiers.append(
            f"blast radius: {other_hosts} other hosts in 24h "
            f"(>= {cfg.RULE_6_BLAST_RADIUS_MIN_OTHER_HOSTS}) — "
            + (
                f"{level} -> {escalated}"
                if escalated != level
                else f"already at {level}, no further escalation possible"
            )
        )
        level = escalated

    return {
        "impact_level": level,
        "impact_governing_subscore": governing,
        "impact_modifiers_applied": modifiers,
        "impact_rule_status": cfg.IMPACT_RULE_STATUS,
        "asset_impact_level": asset_level,
        "asset_impact_reason": asset_reason,
        "technical_impact_level": technical_level,
        "technical_impact_reason": technical_reason,
        "impact_before_modifiers": base_level,
        "other_host_count": other_hosts,
    }


# ---------------------------------------------------------------------------
# EVIDENCE QUALITY — newscoresystem.md §4.5
# ---------------------------------------------------------------------------


def _evidence_completeness_pct(evidence: EnrichedEvidence) -> float:
    """How much the ALERT ITSELF yielded — 8 presence checks on
    `CanonicalAlert`. Carried over unchanged from v1.

    This is deliberately NOT the same signal as `gap_count` below, even though
    both feed evidence quality. Completeness measures how rich the alert was;
    gap_count measures how many of Stage 1's tool calls failed. Deriving both
    from one signal would penalise the same fact twice under two names."""
    alert = evidence.canonical_alert
    checks = [
        alert.host is not None,
        alert.user is not None,
        alert.process is not None,
        alert.network is not None,
        alert.file is not None,
        bool(alert.observables.external_ips or alert.observables.domains or alert.observables.urls),
        not alert.observables.hashes.is_empty(),
        bool(alert.cortex_results),
    ]
    assert len(checks) == cfg.EVIDENCE_COMPLETENESS_FIELD_COUNT
    return 100.0 * sum(checks) / cfg.EVIDENCE_COMPLETENESS_FIELD_COUNT


def assess_evidence_quality(evidence: EnrichedEvidence) -> dict:
    """`newscoresystem.md` §4.5. The two inputs are **ANDed**, not averaged: a
    rich alert whose backends all failed cannot reach HIGH, and neither can a
    thin alert with clean backends. Each measures a different way of not
    knowing enough, and either one alone is sufficient to doubt the result.

    §4.5 specifies this mechanism but gives no thresholds, and §5.1's worksheet
    has no row for them — the boundaries in `scoring_config.py` are a
    documented gap-fill by this repo, PROVISIONAL and flagged for review
    alongside the spec's own seven rows."""
    completeness = _evidence_completeness_pct(evidence)
    gaps = len(evidence.investigation_gaps)

    if (
        completeness >= cfg.EVIDENCE_QUALITY_HIGH_MIN_COMPLETENESS_PCT
        and gaps <= cfg.EVIDENCE_QUALITY_HIGH_MAX_GAPS
    ):
        quality = "HIGH"
    elif (
        completeness >= cfg.EVIDENCE_QUALITY_MODERATE_MIN_COMPLETENESS_PCT
        and gaps <= cfg.EVIDENCE_QUALITY_MODERATE_MAX_GAPS
    ):
        quality = "MODERATE"
    else:
        quality = "LOW"

    return {
        "evidence_quality": quality,
        "evidence_completeness_pct": completeness,
        "gap_count": gaps,
    }


# ---------------------------------------------------------------------------
# The full Stage 5 computation
# ---------------------------------------------------------------------------


def compute_priority(context: ContextualAssessment, evidence: EnrichedEvidence) -> dict:
    """`newscoresystem.md` §4 end to end:

    ```
    Priority = MATRIX[Likelihood][Impact]
    if Evidence Quality == LOW: Priority = escalate_one_band(Priority)
    ```

    Returns a plain dict carrying exactly `newscoresystem.md` §8's audit-trail
    fields, plus a `components` dict of every named sub-term. `nodes/score.py`
    wraps it into `PriorityScore`.

    **No `TriageVerdict` parameter.** v1 read `verdict.verdict` for a
    consistency bonus; v3 has no such term — Stage 4's judgment is reported
    alongside the priority, never folded into it.
    """
    likelihood = assess_likelihood(evidence)
    impact = assess_impact(context, evidence)
    quality = assess_evidence_quality(evidence)

    matrix_priority = cfg.PRIORITY_MATRIX.get(
        (likelihood["likelihood_level"], impact["impact_level"]), cfg.PRIORITY_FALLBACK
    )

    # §4.5's single override. STANDARD, needs no calibration: a safety default
    # that errs deliberately in the safe direction ("escalate under
    # uncertainty, downgrade later"). One-way — it can never DE-escalate.
    override_applied = quality["evidence_quality"] == cfg.EVIDENCE_QUALITY_ESCALATION_TRIGGER
    final_priority = escalate_one_band(matrix_priority) if override_applied else matrix_priority

    result = {
        # --- §8's audit trail, in the order that document lists it ---
        **likelihood,
        "impact_level": impact["impact_level"],
        "impact_governing_subscore": impact["impact_governing_subscore"],
        "impact_modifiers_applied": impact["impact_modifiers_applied"],
        "impact_rule_status": impact["impact_rule_status"],
        "matrix_priority": matrix_priority,
        "matrix_status": cfg.MATRIX_STATUS,
        "evidence_quality": quality["evidence_quality"],
        "evidence_quality_override_applied": override_applied,
        "final_priority": final_priority,
        "deployment_mode": cfg.DEPLOYMENT_MODE,
        "components": {
            "asset_impact_level": impact["asset_impact_level"],
            "asset_impact_reason": impact["asset_impact_reason"],
            "technical_impact_level": impact["technical_impact_level"],
            "technical_impact_reason": impact["technical_impact_reason"],
            "impact_before_modifiers": impact["impact_before_modifiers"],
            "other_host_count": impact["other_host_count"],
            "evidence_completeness_pct": quality["evidence_completeness_pct"],
            "gap_count": quality["gap_count"],
            "closed_case_sample": _tp_ratio(evidence)[0],
            "closed_case_tp_ratio": round(_tp_ratio(evidence)[1], 4),
        },
    }
    result["explanation"] = build_explanation(result)
    return result


def build_explanation(result: dict) -> str:
    """`newscoresystem.md` §8's single-sentence explanation — the artifact that
    makes the whole v3 honesty commitment real. Every number the system emits
    states, in the output itself, whether it has been validated. A reviewer
    never has to take the system's confidence on faith."""
    parts = [
        f"Likelihood={result['likelihood_level']} "
        f"(rule {result['likelihood_rule_fired']}, {result['likelihood_rule_status']}: "
        f"{result['likelihood_rule_reason']})",
        f"Impact={result['impact_level']} "
        f"({result['impact_governing_subscore']}, {result['impact_rule_status']})",
        f"matrix={result['matrix_priority']} ({result['matrix_status']})",
        f"Evidence Quality={result['evidence_quality']}",
    ]
    if result["evidence_quality_override_applied"]:
        parts.append(
            f"escalated {result['matrix_priority']} -> {result['final_priority']} "
            "on LOW evidence quality"
        )
    for modifier in result["impact_modifiers_applied"]:
        parts.append(modifier)
    parts.append(f"mode={result['deployment_mode']}")
    return ", ".join(parts) + "."
