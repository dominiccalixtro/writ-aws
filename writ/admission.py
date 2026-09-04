"""Admission policy: sec. 7 and sec. 3 (invariants) of docs/IMPLEMENTATION_PLAN.md.

Admission is deterministic (sec. 3.4) and deny-by-default (sec. 3.5). No
language model is consulted here (invariant I2). This module is the only
place a Petition may become a Writ or a Refusal.
"""

from __future__ import annotations

from dataclasses import dataclass

from writ.petition import Petition
from writ.writs import Writ

# sec. 7.1 — explicit allowlist, no wildcards. Populated during Phase 2 build-out.
ALLOWED_ACTIONS: frozenset[str] = frozenset()

# sec. 7.6 — always classifies "human", never overridable by configuration.
ALWAYS_HUMAN_PREFIXES: tuple[str, ...] = ("iam:", "cloudtrail:", "kms:", "organizations:")


@dataclass(frozen=True)
class Refusal:
    """A terminal decision for one petition (sec. 3.7). Never auto-retried."""

    finding_id: str
    reason: str


def admit(petition: Petition, sandbox_account_id: str) -> Writ | Refusal:
    """Decide admission for one petition. Deterministic; no model calls (I2).

    Pipeline (sec. 3 diagram): schema is already validated by the caller via
    writ.petition.parse_petition; this function performs, in order:
      1. static action allowlist check (sec. 7.1-7.2)
      2. resource-scope check: sandbox account + sandbox tag (sec. 7.3)
      3. terraform plan gate, when the petition proposes a diff (sec. 7.4)
      4. blast-radius classification (sec. 7.5-7.6)
    Every path returns Writ or Refusal — never raises for a bad petition.
    """
    raise NotImplementedError("sec. 7 — admission policy not yet implemented")
