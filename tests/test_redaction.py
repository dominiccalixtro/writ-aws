"""sec. 5.4 and acceptance A1.2 — no real AWS account ID is ever committed.

sec. 5.4 requires a test asserting that no fixture carries a 12-digit sequence
matching the operator's real account ID. A1.2 widens that to every committed
file. This module implements the wider rule, because the narrower one is a
subset of it and sec. 1.5 gives the stricter constraint.

The test cannot name the operator's real account ID: committing that value is
precisely what it exists to prevent. It works the other way round — every
12-digit sequence in a committed file must be a *documented placeholder* on the
allowlist below. An unrecognised one fails the suite, so adding a placeholder is
an explicit, reviewable edit rather than something a regex quietly waves through.
"""

from __future__ import annotations

import re
import subprocess
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Documentation placeholders, not real accounts. 123456789012 is the canonical
# example account ID used throughout AWS's own documentation. Every entry here is
# a value that is safe to commit *because it belongs to no one*. Adding to this
# list asserts exactly that; do not add a value merely because it looks fake.
ALLOWED_ACCOUNT_PLACEHOLDERS = frozenset({"123456789012"})

# An account ID is exactly 12 digits. The lookarounds keep a longer digit run
# (a timestamp, a test literal like "9" * 5000) from matching a 12-digit window
# inside it, which would be a false positive rather than a leaked account.
ACCOUNT_ID_PATTERN = re.compile(r"(?<!\d)\d{12}(?!\d)")

# Scanned regardless of git: directories that are never committed. `.lab/` holds
# live sandbox scratch policy, and is gitignored precisely because it is not safe
# to commit.
NEVER_COMMITTED = ("__pycache__", ".git", ".lab", ".runs", ".venv", "venv", ".terraform")

# Binary payloads have no reviewable text; a leaked ID would be a different
# problem detected a different way.
BINARY_SUFFIXES = frozenset(
    {".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".whl", ".pyc"}
)


def _git_tracked_files() -> list[Path] | None:
    """Files git would commit: tracked, plus untracked that are not ignored.

    `--others --exclude-standard` matters here because the repository may have no
    commits yet, in which case `--cached` alone returns nothing and the scan would
    pass by scanning nothing at all.
    """
    try:
        result = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=REPO_ROOT,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    names = result.stdout.decode("utf-8", errors="replace").split("\0")
    return [REPO_ROOT / name for name in names if name]


def _walked_files() -> list[Path]:
    """Fallback enumeration for when git is unavailable.

    Deliberately not a skip: a redaction check that silently does nothing is the
    failure mode this module exists to prevent.
    """
    found = []
    for path in REPO_ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in NEVER_COMMITTED for part in path.relative_to(REPO_ROOT).parts):
            continue
        found.append(path)
    return found


def committed_files() -> list[Path]:
    """Every file that would land in a commit, git's answer preferred."""
    tracked = _git_tracked_files()
    candidates = tracked if tracked is not None else _walked_files()
    return [
        path
        for path in candidates
        if path.is_file()
        and path.suffix.lower() not in BINARY_SUFFIXES
        and not any(part in NEVER_COMMITTED for part in path.relative_to(REPO_ROOT).parts)
    ]


def scan(path: Path) -> set[str]:
    """Every 12-digit sequence in `path` that is not an allowlisted placeholder."""
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return set()
    return set(ACCOUNT_ID_PATTERN.findall(text)) - ALLOWED_ACCOUNT_PLACEHOLDERS


class AccountIdRedactionTests(unittest.TestCase):
    """sec. 5.4, A1.2 — offline, credential-free, and unable to pass vacuously."""

    def test_the_scan_covers_a_plausible_set_of_files(self) -> None:
        """A scan of nothing would pass every assertion below it."""
        files = committed_files()
        self.assertGreater(len(files), 5, "redaction scan found almost no files to scan")
        names = {path.name for path in files}
        for expected in ("IMPLEMENTATION_PLAN.md", "RUNBOOK.md", "petition.py"):
            self.assertIn(expected, names, f"redaction scan did not reach {expected}")

    def test_no_unrecognised_account_id_in_any_committed_file(self) -> None:
        """A1.2 — the only 12-digit sequences committed are documented placeholders."""
        offenders = {}
        for path in committed_files():
            found = scan(path)
            if found:
                offenders[str(path.relative_to(REPO_ROOT))] = sorted(found)
        self.assertEqual(
            offenders,
            {},
            "unrecognised 12-digit sequence(s) in committed files. If these are "
            "documentation placeholders, add them to ALLOWED_ACCOUNT_PLACEHOLDERS "
            f"with a comment saying why they are safe: {offenders}",
        )

    def test_fixtures_carry_no_unrecognised_account_id(self) -> None:
        """sec. 5.4 — stated separately because it is the narrower requirement."""
        fixtures = REPO_ROOT / "tests" / "fixtures"
        offenders = {
            str(path.relative_to(REPO_ROOT)): sorted(scan(path))
            for path in fixtures.rglob("*")
            if path.is_file() and scan(path)
        }
        self.assertEqual(offenders, {}, f"account ID in fixture(s): {offenders}")

    def test_an_unrecognised_account_id_would_be_caught(self) -> None:
        """The detector must be able to fail, or it asserts nothing.

        Exercised against literal text rather than the repository, so the check
        never depends on a real leak existing to prove it works.
        """
        # Assembled rather than written literally for one narrow reason: a probe
        # that is a committed 12-digit sequence would be caught by the scan above
        # and fail the suite. This is the detector's own negative fixture, not
        # data dodging the control — the placeholders in the rest of the suite
        # are written out in full.
        probe = "1" * 12
        self.assertEqual(scan_text(f"account {probe} here"), {probe})
        self.assertEqual(scan_text("account 123456789012 here"), set())
        # A longer digit run is not an account ID and must not false-positive.
        self.assertEqual(scan_text("9" * 20), set())


def scan_text(text: str) -> set[str]:
    """The scan's matching rule, applied to a string (used by the self-check)."""
    return set(ACCOUNT_ID_PATTERN.findall(text)) - ALLOWED_ACCOUNT_PLACEHOLDERS


if __name__ == "__main__":
    unittest.main()
