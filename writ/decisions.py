"""Decision records: sec. 3.8 and sec. 7.8 of docs/IMPLEMENTATION_PLAN.md.

Every admission or refusal produces a persisted decision record before any
subsequent step. Written with newline="" so digests stay stable across
platforms (mirrors sentinelcloud-engineering-loop's _write_json convention).
"""

from __future__ import annotations

from pathlib import Path

from writ.admission import Refusal
from writ.writs import Writ


def record_decision(outcome: Writ | Refusal, run_dir: Path) -> Path:
    """Persist one admission/refusal decision under run_dir. Never mutates outcome."""
    raise NotImplementedError("sec. 3.8, 7.8 — decision recording not yet implemented")
