"""Redact one captured artifact before it is committed as a fixture (sec. 5.4).

Run on the operator's machine, between capture and commit:

    python -m tools.redact_fixture --account <sandbox-id>=123456789012 \\
        .capture/finding-sg.json tests/fixtures/findings/security-group-open-ingress.json

Replaces, in order:

  - each --replace OLD=NEW literal (an SSO user name, an Identity Center role
    hash — anything operator-specific the patterns below cannot know);
  - each --account REAL=PLACEHOLDER. The placeholder must already be on the
    allowlist in tests/test_redaction.py, which is where adding one is reviewed;
  - AWS key and unique IDs (AKIA..., ASIA..., AROA..., ...) with a fixed
    EXAMPLE form. A CloudTrail event carries the caller's session key ID;
  - S3 canonical user IDs and Identity Center identity store IDs;
  - globally routable IP addresses with documentation addresses (RFC 5737,
    RFC 3849). A CloudTrail event carries the caller's source IP — the
    operator's home address. 0.0.0.0/0 and private ranges are kept: the first
    is the point of the security-group finding, the second identifies nothing;
  - email addresses with operator@example.com.

Then it refuses to write the output if any 12-digit sequence remains that is not
an allowed placeholder — the sec. 5.4 check, run before the file exists rather
than after it is committed. It works on text, not JSON, so it treats a JSON Lines
plan and a CloudTrail event alike and cannot drop a field it does not understand.

It finds what it was told to look for. The output still needs a human read.

Stdlib only; no network (sec. 5.5).
"""

from __future__ import annotations

import argparse
import ipaddress
import re
import sys
from pathlib import Path

# One source of truth: the placeholders the redaction test accepts, and the
# pattern it scans with. A redactor that disagreed with the test would produce
# output the suite rejects, or worse, accept output the suite would.
from tests.test_redaction import ACCOUNT_ID_PATTERN, ALLOWED_ACCOUNT_PLACEHOLDERS

# IAM unique-ID prefixes (access keys, roles, users, groups, instance profiles,
# managed policies, certificates, public keys, bearer tokens, context keys).
# 20 characters in total.
AWS_ID_PATTERN = re.compile(
    r"(?<![A-Z0-9])(AKIA|ASIA|AROA|AIDA|AGPA|AIPA|ANPA|ANVA|ASCA|APKA|ABIA|ACCA)"
    r"[A-Z0-9]{16}(?![A-Z0-9])"
)
_EXAMPLE_ID_SUFFIX = "EXAMPLE000000000"  # 16 characters, as the real suffix

# An S3 canonical user ID (ASFF Details.AwsS3Bucket.OwnerId): 64 hex characters,
# one per account, as identifying as the account ID itself.
CANONICAL_ID_PATTERN = re.compile(r"(?<![0-9A-Fa-f])[0-9a-f]{64}(?![0-9A-Fa-f])")
EXAMPLE_CANONICAL_ID = "0123456789abcdef" * 4
# An IAM Identity Center identity store ID, as CloudTrail carries it.
IDENTITY_STORE_PATTERN = re.compile(r"(?<![A-Za-z0-9-])d-[0-9a-f]{10}(?![A-Za-z0-9])")
EXAMPLE_IDENTITY_STORE = "d-0000000000"

# Bounded by characters an address cannot sit inside. Without the letter and
# hyphen bounds, the "1::" in "ap-southeast-1::product" and the "::a" in
# "iam::aws" parse as routable IPv6 and get rewritten inside ARNs. A trailing
# full stop is allowed, so an address ending a sentence is still found.
IPV4_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_-])(?<![0-9]\.)(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9A-Za-z_-]|\.[0-9])"
)
IPV6_PATTERN = re.compile(
    r"(?<![A-Za-z0-9_.:-])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}"
    r"(?![A-Za-z0-9_:-]|\.[A-Za-z0-9])"
)
EMAIL_PATTERN = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
EXAMPLE_EMAIL = "operator@example.com"


class RedactionError(Exception):
    """The input cannot be made safe to commit by this tool alone."""


def redact(text: str, accounts: dict[str, str], literals: dict[str, str]) -> str:
    """Return `text` with every known identifier replaced. Deterministic."""
    for placeholder in accounts.values():
        if placeholder not in ALLOWED_ACCOUNT_PLACEHOLDERS:
            raise RedactionError(
                f"placeholder {placeholder!r} is not in ALLOWED_ACCOUNT_PLACEHOLDERS "
                "(tests/test_redaction.py); add it there, with a comment saying why "
                "it belongs to no one, before redacting to it"
            )
    for real in accounts:
        if not ACCOUNT_ID_PATTERN.fullmatch(real):
            raise RedactionError(f"{real!r} is not a 12-digit account ID")

    # Longest first, so a literal that contains another is replaced whole.
    for old in sorted(literals, key=len, reverse=True):
        if not old:
            raise RedactionError("an empty --replace literal would match everywhere")
        text = text.replace(old, literals[old])
    for real, placeholder in accounts.items():
        text = re.sub(rf"(?<!\d){real}(?!\d)", placeholder, text)

    text = AWS_ID_PATTERN.sub(lambda m: m.group(1) + _EXAMPLE_ID_SUFFIX, text)
    text = CANONICAL_ID_PATTERN.sub(EXAMPLE_CANONICAL_ID, text)
    text = IDENTITY_STORE_PATTERN.sub(EXAMPLE_IDENTITY_STORE, text)
    text = _replace_global_addresses(text)
    return EMAIL_PATTERN.sub(EXAMPLE_EMAIL, text)


def residue(text: str) -> set[str]:
    """12-digit sequences that no placeholder accounts for (sec. 5.4)."""
    return set(ACCOUNT_ID_PATTERN.findall(text)) - ALLOWED_ACCOUNT_PLACEHOLDERS


def _replace_global_addresses(text: str) -> str:
    """Map each distinct routable address to its own documentation address.

    Distinct stays distinct, so a fixture showing two callers still shows two.
    """
    seen: dict[str, str] = {}

    def substitute(match: re.Match[str], version: int) -> str:
        token = match.group(0)
        try:
            address = ipaddress.ip_address(token)
        except ValueError:
            return token
        if address.version != version or not address.is_global:
            return token
        if token not in seen:
            n = sum(1 for v in seen.values() if (":" in v) == (version == 6)) + 1
            seen[token] = f"192.0.2.{n}" if version == 4 else f"2001:db8::{n:x}"
        return seen[token]

    text = IPV4_PATTERN.sub(lambda m: substitute(m, 4), text)
    return IPV6_PATTERN.sub(lambda m: substitute(m, 6), text)


def _pairs(values: list[str], flag: str) -> dict[str, str]:
    pairs: dict[str, str] = {}
    for value in values:
        old, sep, new = value.partition("=")
        if not sep:
            raise RedactionError(f"{flag} expects OLD=NEW, got {value!r}")
        pairs[old] = new
    return pairs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m tools.redact_fixture",
        description="Redact a captured artifact for commit as a fixture (sec. 5.4).",
    )
    parser.add_argument("source", type=Path, help="raw capture, never committed")
    parser.add_argument("destination", type=Path, help="redacted fixture to write")
    parser.add_argument("--account", action="append", default=[], metavar="REAL=PLACEHOLDER")
    parser.add_argument("--replace", action="append", default=[], metavar="OLD=NEW")
    args = parser.parse_args(argv)

    try:
        # newline="" in and out: the bytes that are not identifiers survive
        # unchanged, line endings included (sec. 7.8's reasoning, applied here).
        with args.source.open(encoding="utf-8", errors="strict", newline="") as handle:
            text = handle.read()
        redacted = redact(
            text, _pairs(args.account, "--account"), _pairs(args.replace, "--replace")
        )
    except (OSError, UnicodeDecodeError, RedactionError) as exc:
        print(f"redact_fixture: {exc}", file=sys.stderr)
        return 2

    leftover = residue(redacted)
    if leftover:
        print(
            f"redact_fixture: {len(leftover)} unrecognised 12-digit sequence(s) remain; "
            "nothing written. Map each with --account, or confirm it is not an "
            "account ID and handle it with --replace.",
            file=sys.stderr,
        )
        return 1

    args.destination.parent.mkdir(parents=True, exist_ok=True)
    with args.destination.open("w", encoding="utf-8", newline="") as handle:
        handle.write(redacted)
    print(f"redact_fixture: wrote {args.destination}; read it before committing.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
