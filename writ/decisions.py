"""Decision records: sec. 3.8, 3.8.1 and sec. 7.8 of docs/IMPLEMENTATION_PLAN.md.

Every admission or refusal produces a persisted decision record before any
subsequent step. Written with newline="" so digests stay stable across
platforms (mirrors sentinelcloud-engineering-loop's _write_json convention).

sec. 3.8.1 adds three obligations this module carries:

  - a refusal at schema validation (sec. 6.5) is a decision, and is recorded
    like any other — the diagram in sec. 3 places schema validation inside
    admission, and its "refused" branch leads to a decision record;
  - every record names the petition it decided, by the SHA-256 of the
    petition's raw bytes, so two petitions for one finding are two decisions
    rather than one record read twice. It also names the sandbox account it
    was decided against: the outcome is a function of both, and a record that
    omitted either could not be reproduced;
  - no record replaces the record of a different decision. The filename carries
    a digest of the record's own bytes, so an identical decision lands on its
    own file and a different one cannot land on anybody else's.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

from writ.admission import Refusal, RefusalReason
from writ.petition import PetitionError
from writ.writs import Writ

# 2: records name their petition (petition_sha256) and sandbox, and parse
# refusals are recorded (sec. 3.8.1). A version 1 reader must assume none of it.
RECORD_VERSION = 2

# A finding id reaches this module from an ASFF finding, which sec. 3.1 defines
# as attacker-controlled. It is therefore never used as a path component as it
# stands: an id of "../../authorized" would otherwise place a record outside the
# run directory, and a real Security Hub id (an ARN) contains ":" and "/", which
# are not legal in a Windows filename at all.
_UNSAFE_FOR_FILENAME = re.compile(r"[^a-z0-9]+")
_SLUG_LIMIT = 60

_SHA256_HEX = re.compile(r"[0-9a-f]{64}")
_ACCOUNT_ID = re.compile(r"[0-9]{12}")

# Every PetitionError message opens with the clause it enforces ("sec. 6.4 —
# ..."). Only that clause is recorded; the rest of the message can quote the
# petition, and petition text is attacker-controlled (sec. 3.1).
_SECTION_PREFIX = re.compile(r"sec\. \d+(?:\.\d+)*")
# sec. 6.5 — the totality clause, for a message that names no section.
_PARSE_FALLBACK_SECTION = "sec. 6.5"

# 16 hex characters (64 bits) of the record digest. The name only has to keep
# different records apart; record_decision still refuses to replace a file
# whose bytes differ, so a collision fails loudly rather than overwriting.
_RECORD_DIGEST_CHARS = 16

Outcome = Writ | Refusal | PetitionError


def record_decision(
    outcome: Outcome, run_dir: Path, *, petition_sha256: str, sandbox_account_id: str
) -> Path:
    """Persist one decision under run_dir, bound to what it decided and against what.

    `outcome` is what admission produced: a Writ, a Refusal, or the PetitionError
    that refused the petition at parse (sec. 6.5, 3.8.1). `petition_sha256` is
    the hex SHA-256 of the petition's raw bytes; `sandbox_account_id` is the
    operator's sandbox the decision was made against (sec. 7.3.1). Keyword-only
    because a record that omits either cannot be reproduced.

    Returns the path written. Re-recording an identical decision is idempotent
    — same bytes, same name. A file already at the name with different bytes
    raises FileExistsError and is left untouched (sec. 3.8.1).
    """
    # Serialise before touching the filesystem. _record_body is what rejects a
    # non-outcome or a malformed binding, and a rejected call should leave no
    # directory behind it.
    body = json.dumps(
        _record_body(outcome, petition_sha256, sandbox_account_id), indent=2, sort_keys=True
    ) + "\n"
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / _record_name(outcome, body.encode("utf-8"))
    _write_once(path, body)
    return path


def _write_once(path: Path, body: str) -> None:
    """Create `path` holding `body` whole, or confirm it already does.

    The record is written to a temporary file and hard-linked into place, so
    its name only ever points at a complete record: a write that fails part-way
    leaves nothing under the name, and a retry succeeds. os.link refuses an
    existing name, which is what keeps sec. 3.8.1's "never replaced" free of a
    check-then-write race.
    """
    data = body.encode("utf-8")
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".record-", suffix=".tmp")
    try:
        # sec. 7.8 — newline="" stops Python translating "\n" to "\r\n" on
        # Windows, which would change the bytes, and so the digest, of an
        # identical decision.
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            if path.read_bytes() != data:
                raise FileExistsError(
                    f"sec. 3.8.1 — {path} already holds a different decision record; "
                    "a record is never replaced"
                ) from None
    finally:
        os.unlink(temporary)


def _record_body(
    outcome: Outcome, petition_sha256: str, sandbox_account_id: str
) -> dict[str, object]:
    """The record's content. Deterministic: no timestamp, no host, no run id.

    sec. 7.8 exists so identical decisions digest identically. A clock reading
    would defeat that, and nothing in sec. 3.8 asks for one — when a decision was
    made belongs to whatever writes the run directory, not to the decision.
    """
    if not isinstance(petition_sha256, str) or not _SHA256_HEX.fullmatch(petition_sha256):
        raise ValueError(
            "petition_sha256 must be 64 lowercase hex characters — the SHA-256 of "
            "the petition's raw bytes (sec. 3.8.1)"
        )
    if not isinstance(sandbox_account_id, str) or not _ACCOUNT_ID.fullmatch(sandbox_account_id):
        raise ValueError("sandbox_account_id must be a 12-digit AWS account ID (sec. 7.3.1)")
    if isinstance(outcome, Writ):
        return {
            "record_version": RECORD_VERSION,
            "decision": "writ",
            "finding_id": outcome.finding_id,
            "petition_sha256": petition_sha256,
            "sandbox_account_id": sandbox_account_id,
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
            "petition_sha256": petition_sha256,
            "sandbox_account_id": sandbox_account_id,
            "reason": outcome.reason.value,
            "section": outcome.section,
        }
    if isinstance(outcome, PetitionError):
        # An unparsed petition has no finding id this broker can vouch for. The
        # petition digest is what identifies it, and the only text recorded is
        # the clause that refused it — never the message, which can quote the
        # petition (sec. 3.1).
        return {
            "record_version": RECORD_VERSION,
            "decision": "refusal",
            "finding_id": None,
            "petition_sha256": petition_sha256,
            "sandbox_account_id": sandbox_account_id,
            "reason": RefusalReason.PETITION_UNPARSEABLE.value,
            "section": _parse_section(outcome),
        }
    raise TypeError(
        f"not an admission outcome: {type(outcome).__name__}. sec. 3.8 records "
        "writs and refusals; anything else means admission returned something "
        "it should not have."
    )


def _parse_section(error: PetitionError) -> str:
    match = _SECTION_PREFIX.match(str(error))
    return match.group(0) if match else _PARSE_FALLBACK_SECTION


def _record_name(outcome: Outcome, data: bytes) -> str:
    """Filename for one decision. Attacker-controlled text never lands raw.

    The slug is lossy, so two different finding ids can collapse to the same
    one. An 8-character digest of the original id keeps their records distinct
    without putting the id itself in the path. The trailing record digest keeps
    two different decisions about one finding distinct (sec. 3.8.1).
    """
    kind = "writ" if isinstance(outcome, Writ) else "refusal"
    record_digest = hashlib.sha256(data).hexdigest()[:_RECORD_DIGEST_CHARS]
    if isinstance(outcome, PetitionError):
        return f"unparsed-{kind}-{record_digest}.json"
    finding_id = outcome.finding_id
    slug = _UNSAFE_FOR_FILENAME.sub("-", finding_id.lower()).strip("-")[:_SLUG_LIMIT]
    id_digest = hashlib.sha256(finding_id.encode("utf-8")).hexdigest()[:8]
    # An id of "../.." or "" slugs to nothing; the digest still identifies it.
    stem = f"{slug}-{id_digest}" if slug else f"finding-{id_digest}"
    return f"{stem}-{kind}-{record_digest}.json"
