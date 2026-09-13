"""Decision records: sec. 3.8 and sec. 7.8 of docs/IMPLEMENTATION_PLAN.md.

Every admission or refusal produces a persisted decision record before any
subsequent step. Written with newline="" so digests stay stable across
platforms (mirrors sentinelcloud-engineering-loop's _write_json convention).
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from writ.admission import Refusal
from writ.writs import Writ

RECORD_VERSION = 1

# A finding id reaches this module from an ASFF finding, which sec. 3.1 defines
# as attacker-controlled. It is therefore never used as a path component as it
# stands: an id of "../../authorized" would otherwise place a record outside the
# run directory, and a real Security Hub id (an ARN) contains ":" and "/", which
# are not legal in a Windows filename at all.
_UNSAFE_FOR_FILENAME = re.compile(r"[^a-z0-9]+")
_SLUG_LIMIT = 60


def record_decision(outcome: Writ | Refusal, run_dir: Path) -> Path:
    """Persist one admission/refusal decision under run_dir. Never mutates outcome.

    Returns the path written. The name is derived deterministically from the
    finding id, so re-recording the same decision rewrites its own record rather
    than accumulating near-duplicates — which suits sec. 3.7, where a refusal is
    terminal rather than something to retry into a second file.
    """
    # Serialise before touching the filesystem. _record_body is what rejects a
    # non-outcome, and a rejected call should leave no directory behind it.
    body = json.dumps(_record_body(outcome), indent=2, sort_keys=True) + "\n"
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / _record_name(outcome)
    # sec. 7.8 — newline="" stops Python translating "\n" to "\r\n" on Windows,
    # which would change the bytes, and so the digest, of an identical decision.
    path.write_text(body, encoding="utf-8", newline="")
    return path


def _record_body(outcome: Writ | Refusal) -> dict[str, object]:
    """The record's content. Deterministic: no timestamp, no host, no run id.

    sec. 7.8 exists so identical decisions digest identically. A clock reading
    would defeat that, and nothing in sec. 3.8 asks for one — when a decision was
    made belongs to whatever writes the run directory, not to the decision.
    """
    if isinstance(outcome, Writ):
        return {
            "record_version": RECORD_VERSION,
            "decision": "writ",
            "finding_id": outcome.finding_id,
            "scope_actions": list(outcome.scope_actions),
            "scope_resource_arns": list(outcome.scope_resource_arns),
            "term_seconds": outcome.term_seconds,
            "classification": outcome.classification,
        }
    if isinstance(outcome, Refusal):
        return {
            "record_version": RECORD_VERSION,
            "decision": "refusal",
            "finding_id": outcome.finding_id,
            "reason": outcome.reason.value,
            "section": outcome.section,
        }
    raise TypeError(
        f"not an admission outcome: {type(outcome).__name__}. sec. 3.8 records "
        "writs and refusals; anything else means admission returned something "
        "it should not have."
    )


def _record_name(outcome: Writ | Refusal) -> str:
    """Filename for one decision. Attacker-controlled text never lands raw.

    The slug is lossy, so two different finding ids can collapse to the same
    one. An 8-character digest of the original id keeps their records distinct
    without putting the id itself in the path.
    """
    finding_id = outcome.finding_id
    kind = "writ" if isinstance(outcome, Writ) else "refusal"
    slug = _UNSAFE_FOR_FILENAME.sub("-", finding_id.lower()).strip("-")[:_SLUG_LIMIT]
    digest = hashlib.sha256(finding_id.encode("utf-8")).hexdigest()[:8]
    if not slug:
        # An id of "../.." or "" slugs to nothing; the digest still identifies it.
        return f"finding-{digest}-{kind}.json"
    return f"{slug}-{digest}-{kind}.json"
