"""Admission policy: sec. 7 and sec. 3 (invariants) of docs/IMPLEMENTATION_PLAN.md.

Admission is deterministic (sec. 3.4) and deny-by-default (sec. 3.5). No
language model is consulted here (invariant I2). This module is the only
place a Petition may become a Writ or a Refusal.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping

from writ.petition import Petition
from writ.writs import Writ


class Band(str, Enum):
    """§7.5 — blast-radius bands. Two only."""
    AUTO = "auto"
    HUMAN = "human"


# §7.5 — the banding rule as data, not code branches. Independently
# reviewable: every permitted action and its band, one table.
ACTION_BANDS: Mapping[str, Band] = MappingProxyType({
    "ec2:RevokeSecurityGroupIngress": Band.AUTO,
})

# §7.1 — derived from ACTION_BANDS so an action cannot be allowlisted
# without a band decision. Two independent structures would drift silently.
ALLOWED_ACTIONS: frozenset[str] = frozenset(ACTION_BANDS)

# §7.6 — applied after the table and overriding it. Not configurable:
# a module constant has nowhere to be overridden from.
ALWAYS_HUMAN_PREFIXES: tuple[str, ...] = ("iam:", "cloudtrail:", "kms:", "organizations:")

for _action in ACTION_BANDS:
    if _action.startswith(ALWAYS_HUMAN_PREFIXES):
        raise ValueError(
            f"ACTION_BANDS entry {_action!r} starts with an ALWAYS_HUMAN_PREFIXES "
            "prefix (sec. 7.6) but is assigned a band (sec. 7.5) — sec. 7.6 "
            "overrides any band assigned here, so the table is contradictory."
        )
    if "*" in _action:
        raise ValueError(
            f"ACTION_BANDS entry {_action!r} contains a wildcard, prohibited "
            "in the allowlist by sec. 7.1."
        )
del _action


# The reason is typed, not prose, specifically so tests can assert *why* a
# petition was refused — otherwise a deny-everything implementation would
# pass the entire suite.
class RefusalReason(str, Enum):
    """Typed refusal reasons. Tests assert on these, not on prose."""
    ACTION_NOT_ALLOWLISTED = "action_not_allowlisted"
    ARN_OUTSIDE_SANDBOX_ACCOUNT = "arn_outside_sandbox_account"
    MALFORMED_ARN = "malformed_arn"
    PLAN_PROHIBITED_DELETE = "plan_prohibited_delete"
    PLAN_UNPARSEABLE = "plan_unparseable"


@dataclass(frozen=True)
class Refusal:
    """A terminal decision for one petition (sec. 3.7). Never auto-retried."""

    finding_id: str
    reason: RefusalReason
    section: str


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
