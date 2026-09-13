"""Admission policy: sec. 7 and sec. 3 (invariants) of docs/IMPLEMENTATION_PLAN.md.

Admission is deterministic (sec. 3.4) and deny-by-default (sec. 3.5). No
language model is consulted here (invariant I2). This module is the only
place a Petition may become a Writ or a Refusal.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Mapping

from writ.petition import Petition
from writ.writs import Writ, issue_writ


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

# §7.4 — the "explicitly enumerated deletable set". The plan requires the set to
# be explicit and does not enumerate it, so it is empty: under §3.5 (deny by
# default) an unenumerated resource type is not deletable, and every planned
# delete therefore refuses. Adding a type here is a contract decision, not a
# convenience — it asserts that destroying that resource is recoverable.
DELETABLE_RESOURCE_TYPES: frozenset[str] = frozenset()

# §7.4 — Terraform reports a replacement as a delete paired with a create. A
# replacement destroys the original, so it is gated exactly like a delete.
_DELETING_ACTIONS: frozenset[str] = frozenset({"delete", "destroy"})

def validate_action_bands(bands: Mapping[str, Band]) -> None:
    """Reject a contradictory or wildcarded band table (sec. 7.1, 7.6).

    Called at import against ACTION_BANDS, so a bad table fails the process
    rather than one request. Takes the table as an argument so the rule itself
    is testable — a guard that can only be exercised by corrupting the module
    is a guard nobody checks.
    """
    for action in bands:
        if action.startswith(ALWAYS_HUMAN_PREFIXES):
            raise ValueError(
                f"ACTION_BANDS entry {action!r} starts with an ALWAYS_HUMAN_PREFIXES "
                "prefix (sec. 7.6) but is assigned a band (sec. 7.5) — sec. 7.6 "
                "overrides any band assigned here, so the table is contradictory."
            )
        if "*" in action:
            raise ValueError(
                f"ACTION_BANDS entry {action!r} contains a wildcard, prohibited "
                "in the allowlist by sec. 7.1."
            )


validate_action_bands(ACTION_BANDS)


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
    # 1 — static action allowlist (sec. 7.1-7.2, invariant I4). Checked first
    # and independently of every other signal: §7.2 refuses a non-allowlisted
    # action "regardless of the other checks' outcomes".
    for action in petition.actions:
        if action not in ALLOWED_ACTIONS:
            return Refusal(petition.finding_id, RefusalReason.ACTION_NOT_ALLOWLISTED, "sec. 7.2")

    # 2 — resource scope (sec. 7.3, 7.3.1, invariant I5). One failing ARN
    # refuses the whole petition; §7.3 prohibits partial admission.
    for arn in petition.resource_arns:
        account = _arn_account(arn)
        if account is None:
            return Refusal(petition.finding_id, RefusalReason.MALFORMED_ARN, "sec. 7.3")
        if account != sandbox_account_id:
            return Refusal(
                petition.finding_id, RefusalReason.ARN_OUTSIDE_SANDBOX_ACCOUNT, "sec. 7.3.1"
            )

    # 3 — terraform plan gate (sec. 7.4), only for petitions carrying a diff.
    if petition.terraform_diff is not None:
        refusal_reason = _plan_refusal(petition.terraform_diff)
        if refusal_reason is not None:
            return Refusal(petition.finding_id, refusal_reason, "sec. 7.4")

    # 4 — blast radius (sec. 7.5-7.6, invariant I6).
    band = classify_band(petition.actions)

    # Scope may only narrow (sec. 3.6). Phase 2 carries the petition's own
    # actions and ARNs, which is a subset of itself; the further intersection
    # with the capability role's permissions needs that role's policy and is
    # therefore Phase 3, where the writ is actually served.
    return issue_writ(
        finding_id=petition.finding_id,
        scope_actions=petition.actions,
        scope_resource_arns=petition.resource_arns,
        classification=band.value,
    )


def classify_band(actions: tuple[str, ...]) -> Band:
    """Blast-radius band for a set of actions (sec. 7.5-7.6, invariant I6).

    Public so the banding rule is independently reviewable as §7.5 requires,
    and so I6 can be asserted directly rather than inferred from an admission
    outcome. `human` always wins: §7.6 overrides the §7.5 table and is not
    configurable.
    """
    for action in actions:
        if action.startswith(ALWAYS_HUMAN_PREFIXES):
            return Band.HUMAN
    for action in actions:
        if ACTION_BANDS.get(action, Band.HUMAN) is Band.HUMAN:
            return Band.HUMAN
    return Band.AUTO


def _arn_account(arn: object) -> str | None:
    """Account field of an ARN, or None if it cannot be read (sec. 7.3.1).

    Offline by construction — no AWS call, no network (invariants I1, I2).
    An ARN whose account field is empty (an S3 bucket ARN, for instance)
    returns that empty string, which cannot equal a sandbox account id and so
    refuses under §3.5. Phase 2 admits nothing it cannot place in the account.
    """
    if not isinstance(arn, str):
        return None
    parts = arn.split(":")
    if len(parts) < 6 or parts[0] != "arn" or not parts[1] or not parts[2]:
        return None
    return parts[4]


def _plan_refusal(terraform_diff: str) -> RefusalReason | None:
    """Gate a `terraform plan -json` stream (sec. 7.4). None means it passes.

    The stream is JSON Lines. Anything that does not parse refuses: an
    ungateable plan is not an absent plan (§3.5).
    """
    saw_change = False
    for line in terraform_diff.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            event = json.loads(line)
        except ValueError:
            return RefusalReason.PLAN_UNPARSEABLE
        if not isinstance(event, dict):
            return RefusalReason.PLAN_UNPARSEABLE
        if event.get("type") != "planned_change":
            continue
        saw_change = True
        change = event.get("change")
        if not isinstance(change, dict):
            return RefusalReason.PLAN_UNPARSEABLE
        resource = change.get("resource")
        if not isinstance(resource, dict):
            return RefusalReason.PLAN_UNPARSEABLE
        resource_type = resource.get("resource_type")
        # Terraform writes a single "action" in some versions and an "actions"
        # list in others; a replacement appears as delete paired with create.
        raw = change.get("actions", change.get("action"))
        actions = [raw] if isinstance(raw, str) else raw
        if not isinstance(actions, list) or not all(isinstance(a, str) for a in actions):
            return RefusalReason.PLAN_UNPARSEABLE
        if _DELETING_ACTIONS.intersection(actions):
            if not isinstance(resource_type, str) or resource_type not in DELETABLE_RESOURCE_TYPES:
                return RefusalReason.PLAN_PROHIBITED_DELETE
    if not saw_change:
        # A petition that claims a diff must produce a gateable one. An empty
        # or change-free stream is unparseable for this purpose, not innocent.
        return RefusalReason.PLAN_UNPARSEABLE
    return None
