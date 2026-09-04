"""Petition schema: sec. 6 of docs/IMPLEMENTATION_PLAN.md.

A petition is a structured, unsigned proposal for remediation emitted by the
agent plane. It carries no authority. Parsing is total (sec. 6.5): every input
either becomes a valid Petition or a typed Refusal — never an unhandled
exception.

On sec. 6.4's fourth clause — "any instruction directed at the broker"
-------------------------------------------------------------------
The first three prohibitions of sec. 6.4 (credentials, role ARNs to assume,
agent-authored policy documents) are structurally detectable and are enforced
below by `_reject_prohibited_structures`.

The fourth is not, and this module deliberately does NOT scan text for
instruction-like patterns. Detecting "an instruction directed at the broker" in
free text is a semantic judgement: sec. 3.4 forbids consulting a model (I2), and
sec. 3.4's determinism requirement rules out tunable heuristics. A keyword
scanner would be security theatre — trivially evaded by paraphrase, and worse
than nothing because it manufactures false confidence.

The clause is satisfied *structurally*, by the closed schema:

  - sec. 6.1 refuses unknown top-level keys, so there is no field in which an
    instruction could be smuggled and later read.
  - sec. 6.3 makes `rationale` — the only free-text field — non-influential on
    admission by construction (see writ.admission).

An instruction therefore has nowhere to live where it would be read as anything
but display text. Do not add a content scanner here believing this was
overlooked; it was considered and rejected.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass

# sec. 6.1 — the schema is explicit and versioned. An absent or unrecognised
# version refuses; there is no "assume latest" path.
SCHEMA_VERSION = "writ.petition/v1"

# sec. 6.1 — closed key set. Anything outside it refuses (never silently ignored).
ALLOWED_TOP_LEVEL_KEYS = frozenset(
    {
        "schema_version",
        "finding_id",
        "actions",
        "terraform_diff",
        "resource_arns",
        "rationale",
    }
)

# sec. 6.2 — every petition declares these. The proposed action set is supplied
# as exactly one of `actions` (AWS API actions) or `terraform_diff`.
REQUIRED_TOP_LEVEL_KEYS = frozenset(
    {"schema_version", "finding_id", "resource_arns", "rationale"}
)

# sec. 6.4 — the fields that determine what a writ *does*. "Role ARNs to assume"
# is a functional category, so the role-ARN and policy-document checks apply here
# and not to `rationale`, which sec. 6.3 renders non-influential and which may
# legitimately name an IAM principal when describing an IAM-related finding.
# Credential detection is deliberately NOT limited to these fields.
STRUCTURAL_FIELDS = frozenset({"actions", "resource_arns", "terraform_diff"})

# sec. 6.5 — bounds applied before or during parsing so that no adversarial
# input reaches a code path that could raise something other than PetitionError.
MAX_PETITION_BYTES = 64 * 1024
MAX_NESTING_DEPTH = 32
MAX_NUMBER_DIGITS = 20

# sec. 6.4 — credential-shaped key names, matched at any nesting depth against a
# key normalised to lowercase alphanumerics. Matching is on the *name*, never on
# the value: a petition has no legitimate reason to carry a field so named.
CREDENTIAL_KEY_MARKERS = (
    "accesskey",
    "secret",
    "sessiontoken",
    "securitytoken",
    "password",
    "passwd",
    "passphrase",
    "privatekey",
    "credential",
    "apikey",
    "bearer",
)

# sec. 6.4 — an IAM role ARN, matched at any depth within STRUCTURAL_FIELDS.
# Target resource ARNs (sec. 7.3) name services other than iam/sts, or an iam
# resource type other than a role, and do not match this pattern.
ROLE_ARN_PATTERN = re.compile(
    r"arn:[a-z0-9\-]*:(?:iam|sts)::[0-9]*:(?:role|assumed-role)/",
    re.IGNORECASE,
)

_NON_ALPHANUMERIC = re.compile(r"[^a-z0-9]")


class PetitionError(Exception):
    """Raised for a petition that fails to parse. Never for admission outcomes."""


@dataclass(frozen=True)
class Petition:
    """A parsed, schema-valid petition. Still unsigned; still carries no authority.

    sec. 6.2: finding_id, actions, resource_arns, and rationale are mandatory.
    sec. 6.3: rationale is untrusted display text and MUST NOT reach admission
    logic as anything but data (see writ.admission).
    """

    finding_id: str
    actions: tuple[str, ...]
    resource_arns: tuple[str, ...]
    rationale: str
    schema_version: str = SCHEMA_VERSION
    terraform_diff: str | None = None


def parse_petition(raw: bytes) -> Petition:
    """Parse raw bytes into a Petition, or raise PetitionError (sec. 6.5, 6.1, 6.4).

    Unknown top-level keys, credentials, role ARNs to assume, or broker-directed
    instructions embedded in any field MUST cause a PetitionError here, not a
    downstream refusal.

    Deterministic: a pure function of `raw`. No clock, randomness, environment,
    filesystem, or network is consulted (sec. 3.4).
    """
    text = _decode(raw)
    document = _load_json(text)

    if not isinstance(document, dict):
        raise PetitionError(
            f"sec. 6.1 — petition must be a JSON object, got {type(document).__name__}"
        )

    # sec. 6.4 runs first, so a petition smuggling a credential or a role ARN
    # refuses for that reason regardless of its other defects.
    _reject_prohibited_structures(document)
    _check_schema_version(document)
    _check_key_set(document)

    actions = _action_set(document)
    return Petition(
        finding_id=_require_text(document, "finding_id"),
        actions=actions,
        resource_arns=_require_text_tuple(document, "resource_arns"),
        rationale=_require_rationale(document),
        schema_version=SCHEMA_VERSION,
        terraform_diff=document.get("terraform_diff"),
    )


# --------------------------------------------------------------------------
# sec. 6.5 — decoding and parsing. Every failure below is a PetitionError.
# --------------------------------------------------------------------------


def _decode(raw: object) -> str:
    """Bytes to text, refusing anything that is not a bounded UTF-8 document."""
    if not isinstance(raw, (bytes, bytearray)):
        raise PetitionError(
            f"sec. 6.5 — petition must be raw bytes, got {type(raw).__name__}"
        )
    # Size is checked before decoding so an oversized input is never materialised
    # as text.
    if len(raw) > MAX_PETITION_BYTES:
        raise PetitionError(
            f"sec. 6.5 — petition exceeds {MAX_PETITION_BYTES} bytes"
        )
    try:
        text = bytes(raw).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise PetitionError(f"sec. 6.5 — petition is not valid UTF-8: {exc.reason}") from None
    if not text.strip():
        raise PetitionError("sec. 6.5 — petition is empty")
    return text


def _load_json(text: str) -> object:
    """json.loads with every silent-acceptance hole in the stdlib parser closed."""
    # Depth is bounded *before* parsing. Catching RecursionError instead would
    # leave the interpreter in a degraded state, and sec. 6.5 requires parsing to
    # be total, not merely non-crashing.
    depth = _max_nesting_depth(text)
    if depth > MAX_NESTING_DEPTH:
        raise PetitionError(
            f"sec. 6.5 — petition nests {depth} levels, exceeding {MAX_NESTING_DEPTH}"
        )
    try:
        return json.loads(
            text,
            object_pairs_hook=_object_pairs_hook,
            parse_constant=_parse_constant,
            parse_int=_parse_int,
            parse_float=_parse_float,
        )
    except json.JSONDecodeError as exc:
        raise PetitionError(f"sec. 6.5 — petition is not valid JSON: {exc.msg}") from None
    except ValueError as exc:  # e.g. int literals beyond sys.int_info limits
        raise PetitionError(f"sec. 6.5 — petition is not valid JSON: {exc}") from None


def _max_nesting_depth(text: str) -> int:
    """Deepest bracket nesting in `text`, ignoring brackets inside string literals.

    A single linear pass with no recursion, so it cannot itself overflow.
    """
    depth = 0
    deepest = 0
    in_string = False
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
            deepest = max(deepest, depth)
        elif char in "}]":
            depth -= 1
    return deepest


def _object_pairs_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
    """Refuse duplicate keys at any depth (sec. 6.5).

    json.loads resolves duplicates last-wins and reports nothing, so
    `{"actions": ["safe"], "actions": ["dangerous"]}` parses cleanly to the
    dangerous value while a human reading the raw petition sees the safe one.
    That is a smuggling vector against review, not a formatting quirk.
    """
    seen: set[str] = set()
    for key, _value in pairs:
        if key in seen:
            raise PetitionError(f"sec. 6.5 — duplicate key in petition: {key!r}")
        seen.add(key)
    return dict(pairs)


def _parse_constant(constant: str) -> object:
    """Refuse NaN/Infinity/-Infinity (sec. 6.5).

    Python's json accepts these despite their not being valid JSON. Anything
    re-serializing the petition would emit output other parsers reject, breaking
    digest stability (sec. 7.8).
    """
    raise PetitionError(f"sec. 6.5 — petition contains non-JSON constant {constant}")


def _parse_int(literal: str) -> int:
    if len(literal.lstrip("-")) > MAX_NUMBER_DIGITS:
        raise PetitionError("sec. 6.5 — petition contains an out-of-bounds integer")
    return int(literal)


def _parse_float(literal: str) -> float:
    value = float(literal)
    if not math.isfinite(value):
        raise PetitionError("sec. 6.5 — petition contains a non-finite number")
    return value


# --------------------------------------------------------------------------
# sec. 6.4 — structural prohibitions. Shape and key names only; never content
# semantics (see the module docstring).
# --------------------------------------------------------------------------


def _reject_prohibited_structures(document: dict[str, object]) -> None:
    """Refuse credentials, role ARNs and policy documents (sec. 6.4).

    Two scopes, deliberately different:

      - Credential-shaped keys are refused in *every* field at every depth.
        Credential material in a petition is a hygiene failure whether or not
        anything downstream would read it.
      - Role ARNs and policy-document shapes are refused only in the structural
        fields (STRUCTURAL_FIELDS), because sec. 6.4 prohibits role ARNs *to
        assume* — a functional category. A role ARN named descriptively in the
        rationale is not one, and refusing it would push agents toward vaguer
        rationales, degrading the field humans read during review.

    Both walks are iterative rather than recursive: depth is already bounded, but
    the walk must not be the thing that overflows.
    """
    _walk(document, _reject_credential_key, check_values=False)
    for field in sorted(STRUCTURAL_FIELDS):
        if field in document:
            _walk(document[field], _reject_role_arn, check_values=True)


def _walk(root: object, check_key, *, check_values: bool) -> None:
    """Apply `check_key` to every key at every depth beneath `root`.

    With check_values, also apply the role-ARN check to every string and the
    policy-document shape check to every object, since a policy document is an
    object rather than a key or a string.
    """
    stack: list[object] = [root]
    while stack:
        node = stack.pop()
        if isinstance(node, dict):
            if check_values:
                _reject_policy_document_shape(node)
            for key, value in node.items():
                check_key(key)
                stack.append(value)
        elif isinstance(node, list):
            stack.extend(node)
        elif isinstance(node, str) and check_values:
            _reject_role_arn(node)


def _reject_credential_key(key: object) -> None:
    if not isinstance(key, str):
        return
    normalised = _NON_ALPHANUMERIC.sub("", key.lower())
    for marker in CREDENTIAL_KEY_MARKERS:
        if marker in normalised:
            raise PetitionError(
                f"sec. 6.4 — petition carries a credential-shaped field: {key!r}"
            )


def _reject_role_arn(value: object) -> None:
    if isinstance(value, str) and ROLE_ARN_PATTERN.search(value):
        raise PetitionError(
            "sec. 6.4 — petition names an IAM role ARN; the agent plane may not "
            "propose a role for the broker to assume"
        )


def _reject_policy_document_shape(node: dict[str, object]) -> None:
    """Refuse an agent-authored IAM policy document (sec. 6.4).

    Detected by shape — a Version+Statement pair, or a Statement list — never by
    reading what the statements say.
    """
    normalised = {
        _NON_ALPHANUMERIC.sub("", key.lower()): value
        for key, value in node.items()
        if isinstance(key, str)
    }
    if "statement" not in normalised:
        return
    if "version" in normalised or isinstance(normalised["statement"], (list, dict)):
        raise PetitionError(
            "sec. 6.4 — petition embeds an IAM policy document; policy documents "
            "are not authored by the agent plane"
        )


# --------------------------------------------------------------------------
# sec. 6.1, 6.2 — schema validation.
# --------------------------------------------------------------------------


def _check_schema_version(document: dict[str, object]) -> None:
    if "schema_version" not in document:
        raise PetitionError("sec. 6.1 — petition declares no schema_version")
    declared = document["schema_version"]
    if declared != SCHEMA_VERSION:
        raise PetitionError(
            f"sec. 6.1 — unrecognised schema_version {declared!r}; "
            f"expected {SCHEMA_VERSION!r}"
        )


def _check_key_set(document: dict[str, object]) -> None:
    unknown = sorted(set(document) - ALLOWED_TOP_LEVEL_KEYS)
    if unknown:
        raise PetitionError(
            f"sec. 6.1 — unknown top-level key(s) in petition: {unknown}"
        )
    missing = sorted(REQUIRED_TOP_LEVEL_KEYS - set(document))
    if missing:
        raise PetitionError(f"sec. 6.2 — petition is missing required field(s): {missing}")


def _action_set(document: dict[str, object]) -> tuple[str, ...]:
    """sec. 6.2 — exactly one of `actions` or `terraform_diff` supplies the action set."""
    has_actions = "actions" in document
    has_diff = "terraform_diff" in document
    if has_actions == has_diff:
        raise PetitionError(
            "sec. 6.2 — petition must declare exactly one of 'actions' or "
            "'terraform_diff' as its proposed action set"
        )
    if has_diff:
        diff = document["terraform_diff"]
        if not isinstance(diff, str) or not diff.strip():
            raise PetitionError("sec. 6.2 — 'terraform_diff' must be a non-empty string")
        return ()
    return _require_text_tuple(document, "actions")


def _require_text(document: dict[str, object], key: str) -> str:
    value = document[key]
    if not isinstance(value, str) or not value.strip():
        raise PetitionError(f"sec. 6.2 — {key!r} must be a non-empty string")
    return value


def _require_rationale(document: dict[str, object]) -> str:
    """sec. 6.3 — rationale is untrusted display text; only its type is checked."""
    value = document["rationale"]
    if not isinstance(value, str):
        raise PetitionError("sec. 6.2 — 'rationale' must be a string")
    return value


def _require_text_tuple(document: dict[str, object], key: str) -> tuple[str, ...]:
    value = document[key]
    if not isinstance(value, list) or not value:
        raise PetitionError(f"sec. 6.2 — {key!r} must be a non-empty list")
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise PetitionError(f"sec. 6.2 — every entry in {key!r} must be a non-empty string")
    return tuple(value)
