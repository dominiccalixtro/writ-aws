"""sec. 3.8 and sec. 7.8 — decision records.

sec. 9.2: the adversarial cases here are about the record's *name*, because the
finding id is attacker-controlled (sec. 3.1) and the filename is the one place
it would otherwise reach the operating system.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from writ.admission import Refusal, RefusalReason, admit
from writ.decisions import RECORD_VERSION, record_decision
from writ.petition import Petition
from writ.writs import issue_writ

SANDBOX = "123456789012"
ALLOWED_ACTION = "ec2:RevokeSecurityGroupIngress"
SANDBOX_ARN = f"arn:aws:ec2:ap-southeast-1:{SANDBOX}:security-group/sg-0123456789abcdef0"


class DecisionRecordTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.run_dir = Path(self._tmp.name) / "run"

    def _writ(self, finding_id: str = "finding-1"):
        return issue_writ(
            finding_id=finding_id,
            scope_actions=(ALLOWED_ACTION,),
            scope_resource_arns=(SANDBOX_ARN,),
            classification="auto",
        )

    def _refusal(self, finding_id: str = "finding-1") -> Refusal:
        return Refusal(finding_id, RefusalReason.ACTION_NOT_ALLOWLISTED, "sec. 7.2")

    def test_writ_is_recorded(self) -> None:
        """sec. 3.8 — an admission produces a persisted record."""
        path = record_decision(self._writ(), self.run_dir)
        self.assertTrue(path.is_file())
        body = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(body["decision"], "writ")
        self.assertEqual(body["finding_id"], "finding-1")
        self.assertEqual(body["term_seconds"], 900)
        self.assertEqual(body["classification"], "auto")
        self.assertEqual(body["record_version"], RECORD_VERSION)

    def test_refusal_is_recorded(self) -> None:
        """sec. 3.8 — 'admission and refusal alike'."""
        path = record_decision(self._refusal(), self.run_dir)
        body = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(body["decision"], "refusal")
        self.assertEqual(body["reason"], RefusalReason.ACTION_NOT_ALLOWLISTED.value)
        self.assertEqual(body["section"], "sec. 7.2")

    def test_run_dir_is_created(self) -> None:
        nested = self.run_dir / "deep" / "deeper"
        path = record_decision(self._writ(), nested)
        self.assertTrue(path.is_file())

    def test_record_bytes_are_stable(self) -> None:
        """sec. 7.8 — identical decisions digest identically.

        Written with newline="" so no platform rewrites "\\n" to "\\r\\n", and
        with no timestamp, so the same decision is byte-identical on every run.
        """
        first = record_decision(self._writ(), self.run_dir / "a").read_bytes()
        second = record_decision(self._writ(), self.run_dir / "b").read_bytes()
        self.assertEqual(hashlib.sha256(first).hexdigest(), hashlib.sha256(second).hexdigest())
        self.assertNotIn(b"\r\n", first)

    def test_rerecording_rewrites_rather_than_accumulates(self) -> None:
        """sec. 3.7 — a refusal is terminal, not a second file."""
        record_decision(self._refusal(), self.run_dir)
        record_decision(self._refusal(), self.run_dir)
        self.assertEqual(len(list(self.run_dir.iterdir())), 1)

    def test_writ_and_refusal_for_one_finding_do_not_collide(self) -> None:
        record_decision(self._writ(), self.run_dir)
        record_decision(self._refusal(), self.run_dir)
        self.assertEqual(len(list(self.run_dir.iterdir())), 2)

    def test_outcome_is_not_mutated(self) -> None:
        writ = self._writ()
        before = (writ.finding_id, writ.scope_actions, writ.term_seconds, writ.classification)
        record_decision(writ, self.run_dir)
        self.assertEqual(
            (writ.finding_id, writ.scope_actions, writ.term_seconds, writ.classification), before
        )

    def test_non_outcome_is_refused(self) -> None:
        """sec. 3.8 records writs and refusals; anything else is a bug upstream."""
        with self.assertRaises(TypeError):
            record_decision({"decision": "writ"}, self.run_dir)  # type: ignore[arg-type]
        # A rejected outcome leaves nothing behind: the type check runs before
        # the directory is created.
        self.assertFalse(self.run_dir.exists())


class DecisionRecordNameTests(unittest.TestCase):
    """sec. 3.1 — the finding id is attacker-controlled and becomes a path."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.run_dir = Path(self._tmp.name) / "run"

    def _record(self, finding_id: str) -> Path:
        return record_decision(
            Refusal(finding_id, RefusalReason.MALFORMED_ARN, "sec. 7.3"), self.run_dir
        )

    def test_traversal_in_finding_id_cannot_escape_run_dir(self) -> None:
        for finding_id in (
            "../../escaped",
            "..\\..\\escaped",
            "/etc/passwd",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "....//....//escaped",
        ):
            with self.subTest(finding_id=finding_id):
                path = self._record(finding_id)
                self.assertEqual(path.parent.resolve(), self.run_dir.resolve())
                self.assertTrue(path.is_file())

    def test_real_asff_style_id_is_usable_as_a_filename(self) -> None:
        """A live finding id is an ARN — ':' alone is illegal in a Windows name."""
        arn = (
            f"arn:aws:securityhub:ap-southeast-1:{SANDBOX}:"
            "subscription/aws-foundational-security-best-practices/v/1.0.0/EC2.19/finding/abc-123"
        )
        path = self._record(arn)
        self.assertTrue(path.is_file())
        for illegal in (":", "/", "\\", "*", "?", '"', "<", ">", "|"):
            self.assertNotIn(illegal, path.name)

    def test_empty_and_punctuation_only_ids_still_produce_a_record(self) -> None:
        for finding_id in ("", "///", "...", "---"):
            with self.subTest(finding_id=finding_id):
                self.assertTrue(self._record(finding_id).is_file())

    def test_distinct_ids_that_slug_alike_do_not_overwrite_each_other(self) -> None:
        """The slug is lossy; the digest is what keeps records distinct."""
        first = self._record("finding/1")
        second = self._record("finding:1")
        self.assertNotEqual(first.name, second.name)
        self.assertEqual(len(list(self.run_dir.iterdir())), 2)

    def test_name_is_deterministic(self) -> None:
        self.assertEqual(self._record("finding-1").name, self._record("finding-1").name)


class AdmissionIsRecordableTests(unittest.TestCase):
    """sec. 3.8 — whatever admit() returns must be recordable, both branches."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.run_dir = Path(self._tmp.name) / "run"

    def test_both_admission_branches_record(self) -> None:
        admitted = admit(
            Petition(
                finding_id="finding-ok",
                actions=(ALLOWED_ACTION,),
                resource_arns=(SANDBOX_ARN,),
                rationale="in scope",
            ),
            SANDBOX,
        )
        refused = admit(
            Petition(
                finding_id="finding-bad",
                actions=("s3:DeleteBucket",),
                resource_arns=(SANDBOX_ARN,),
                rationale="out of scope",
            ),
            SANDBOX,
        )
        for outcome in (admitted, refused):
            with self.subTest(outcome=type(outcome).__name__):
                self.assertTrue(record_decision(outcome, self.run_dir).is_file())


if __name__ == "__main__":
    unittest.main()
