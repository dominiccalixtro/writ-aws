"""CLI entry point: reads a fixture finding, prints a writ or a refusal.

Performs no network call in Phases 0-2 (invariant I8, acceptance A2.3).
"""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="writ")
    parser.add_argument("--finding", required=True, help="path to a fixture ASFF finding")
    parser.parse_args(argv)
    print("writ: not yet implemented (sec. 6-7)", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
