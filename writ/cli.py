"""CLI entry point: reads a petition, prints a writ or a typed refusal.

Performs no network call in Phases 0-2 (invariant I8, acceptance A2.3).

On the input: acceptance A2.3 describes running the CLI "against a fixture
finding". Nothing in Phases 0-2 turns a finding into a petition — sec. 1 defines
that as the agent plane's job, and invariant I2 forbids consulting a model
during admission — so the petition, the artifact the agent plane emits, is what
this command consumes. `--finding` remains accepted as an alias so existing
invocations keep working. Closing A2.3 as literally worded needs both the
Phase 1 fixture corpus (sec. 5) and an agent-plane component; neither exists.

The sandbox account id is an operator input, never read from the petition.
A petition that could name its own sandbox account would decide sec. 7.3 for
itself, which is the check it is supposed to be measured against.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from writ.admission import admit
from writ.decisions import record_decision
from writ.petition import PetitionError, parse_petition
from writ.writs import Writ

DEFAULT_RUN_DIR = Path(".runs")

EXIT_ADMITTED = 0
EXIT_REFUSED = 1
EXIT_INPUT_ERROR = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="writ",
        description=(
            "Admit or refuse one petition. Prints the decision record it just "
            "persisted. Serves nothing: no code path here reaches AWS (I8)."
        ),
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--petition", help="path to a petition JSON document")
    source.add_argument("--finding", help=argparse.SUPPRESS)  # A2.3 alias; see module docstring
    parser.add_argument(
        "--sandbox-account-id",
        required=True,
        help="the sandbox account every target ARN must reside in (sec. 7.3.1)",
    )
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=DEFAULT_RUN_DIR,
        help=f"directory for decision records (default: {DEFAULT_RUN_DIR})",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    path = Path(args.petition or args.finding)

    try:
        raw = path.read_bytes()
    except OSError as exc:
        print(f"writ: cannot read {path}: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    # sec. 6.5 — parsing is total: a typed PetitionError, never a traceback.
    try:
        petition = parse_petition(raw)
    except PetitionError as exc:
        print(f"writ: petition refused at parse: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    outcome = admit(petition, args.sandbox_account_id)

    # sec. 3.8 — persisted before any subsequent step, printing included. What
    # reaches stdout is then the recorded bytes themselves, so what an operator
    # reads and what the record digests to cannot drift apart.
    try:
        record_path = record_decision(outcome, args.run_dir)
    except OSError as exc:
        print(f"writ: decision not recorded ({exc}); refusing to report it", file=sys.stderr)
        return EXIT_INPUT_ERROR

    sys.stdout.write(record_path.read_text(encoding="utf-8"))
    print(f"writ: recorded {record_path}", file=sys.stderr)

    return EXIT_ADMITTED if isinstance(outcome, Writ) else EXIT_REFUSED


if __name__ == "__main__":
    raise SystemExit(main())
