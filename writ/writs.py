"""Writ construction: sec. 7.7 of docs/IMPLEMENTATION_PLAN.md.

A writ is an admitted, signed, scoped, expiring order to perform one specific
act. Phases 0-2 construct and print writs but never serve them (sec. 1.4,
invariant I8) — there is no code path here capable of executing one.
"""

from __future__ import annotations

from dataclasses import dataclass, field

MAX_TERM_SECONDS = 900  # sec. 7.7, invariant I7 — never exceeded, never configurable up
TERM_SECONDS = 900  # sec. 7.7 — the STS DurationSeconds minimum equals the I7 ceiling


@dataclass(frozen=True)
class Writ:
    """An admitted order. Scope may only narrow from the petition (sec. 3.6)."""

    finding_id: str
    scope_actions: tuple[str, ...]
    scope_resource_arns: tuple[str, ...]
    # sec. 7.7: the STS DurationSeconds minimum (900) coincides with the I7
    # ceiling (900), so 900 is the sole legal term. init=False makes any other
    # term unconstructible, while the field itself remains on the writ so a
    # decision record still states its own term (sec. 7.8).
    term_seconds: int = field(default=TERM_SECONDS, init=False)
    classification: str  # "auto" | "human" — sec. 7.5, 7.6


def issue_writ(*args, **kwargs) -> Writ:
    """Construct a Writ from an admitted petition. Never serves it (I8)."""
    raise NotImplementedError("sec. 7.7 — writ issuance not yet implemented")
