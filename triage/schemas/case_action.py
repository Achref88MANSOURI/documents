"""Case-action output contract — a deployment addition, not in architecture
v4. See `nodes/case_action.py`'s module docstring and CLAUDE.md's "Case
action" entry for why this Python service writes to TheHive at all
(architecture §1/§3's original design has n8n own every case mutation;
2026-08-21, the user explicitly asked for this service to do it directly
instead, and to always act — no `needs_review` hold-off).

`CaseActionResult` is deliberately NOT a stage boundary in architecture's
original sense (there's no §18 file map entry for it) — it's this
deployment's own addition, following the same "typed Pydantic contract"
discipline every other node output already uses.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from schemas.verdict import ActionableObservable


class CaseActionResult(BaseModel):
    success: bool
    case_id: str = ""
    case_number: int | None = None
    is_new_case: bool = False
    severity: int | None = None  # TheHive's 1-4 scale, as actually written
    stage: str | None = None
    status: str | None = None
    tags: list[str] = Field(default_factory=list)
    comment_added: bool = False
    observables_written: int = 0
    observables_failed: int = 0
    # 2026-08-23: Stage 4's full actionable_observables list, enriched with
    # each item's real TheHive observable_id — reused from what was already
    # on the case where a value matched, newly created otherwise. See
    # nodes/case_action.py's module docstring. observables_written/_failed
    # above count against THIS list now (an old-style bucket write of Stage
    # 3's raw extraction no longer happens here at all).
    actionable_observables_written: list[ActionableObservable] = Field(default_factory=list)
    # Set only when success=False — this node never raises to its caller,
    # same contract as every tools/*.py function (Gap-shaped, but named
    # `error` rather than reusing `Gap` since this isn't a Stage 1 gather
    # gap — the alert always got triaged; only the case write itself failed).
    error: str | None = None
