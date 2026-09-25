"""sec. 3.8, 3.8.1 and sec. 7.8 — decision records.

sec. 9.2: the adversarial cases here are about the record's *name*, because the
finding id is attacker-controlled (sec. 3.1) and the filename is the one place
it would otherwise reach the operating system — and about the record's
*survival*, because a petitioner who could overwrite an earlier record could
erase the evidence of its own refused petition (sec. 3.8.1).
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from writ.admission import Refusal, RefusalReason, admit
from writ.decisions import RECORD_VERSION, record_decision
from writ.petition import Petition, PetitionError
from writ.writs import issue_writ

SANDBOX = "123456789012"
ALLOWED_ACTION = "ec2:RevokeSecurityGroupIngress"
SANDBOX_ARN = f"arn:aws:ec2:ap-southeast-1:{SANDBOX}:security-group/sg-0123456789abcdef0"
# sec. 3.8.1 — records name the petition they decided. Any two distinct byte
# strings serve; these stand in for two different petitions.
PETITION = hashlib.sha256(b"petition one").hexdigest()
OTHER_PETITION = hashlib.sha256(b"petition two").hexdigest()


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
        path = record_decision(self._writ(), self.run_dir, petition_sha256=PETITION, sandbox_account_id=SANDBOX)
        self.assertTrue(path.is_file())
        body = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(body["decision"], "writ")
        self.assertEqual(body["finding_id"], "finding-1")
        self.assertEqual(body["term_seconds"], 900)
        self.assertEqual(body["classification"], "auto")
        self.assertEqual(body["record_version"], RECORD_VERSION)

    def test_refusal_is_recorded(self) -> None:
        """sec. 3.8 — 'admission and refusal alike'."""
        path = record_decision(self._refusal(), self.run_dir, petition_sha256=PETITION, sandbox_account_id=SANDBOX)
        body = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(body["decision"], "refusal")
        self.assertEqual(body["reason"], RefusalReason.ACTION_NOT_ALLOWLISTED.value)
        self.assertEqual(body["section"], "sec. 7.2")

    def test_run_dir_is_created(self) -> None:
        nested = self.run_dir / "deep" / "deeper"
        path = record_decision(self._writ(), nested, petition_sha256=PETITION, sandbox_account_id=SANDBOX)
        self.assertTrue(path.is_file())

    def test_record_bytes_are_stable(self) -> None:
        """sec. 7.8 — identical decisions digest identically.

        Written with newline="" so no platform rewrites "\\n" to "\\r\\n", and
        with no timestamp, so the same decision is byte-identical on every run.
        """
        first = record_decision(self._writ(), self.run_dir / "a", petition_sha256=PETITION, sandbox_account_id=SANDBOX).read_bytes()
        second = record_decision(self._writ(), self.run_dir / "b", petition_sha256=PETITION, sandbox_account_id=SANDBOX).read_bytes()
        self.assertEqual(hashlib.sha256(first).hexdigest(), hashlib.sha256(second).hexdigest())
        self.assertNotIn(b"\r\n", first)

    def test_rerecording_an_identical_decision_is_idempotent(self) -> None:
        """sec. 3.7 — the same refusal of the same petition is one record."""
        record_decision(self._refusal(), self.run_dir, petition_sha256=PETITION, sandbox_account_id=SANDBOX)
        record_decision(self._refusal(), self.run_dir, petition_sha256=PETITION, sandbox_account_id=SANDBOX)
        self.assertEqual(len(list(self.run_dir.iterdir())), 1)

    def test_writ_and_refusal_for_one_finding_do_not_collide(self) -> None:
        record_decision(self._writ(), self.run_dir, petition_sha256=PETITION, sandbox_account_id=SANDBOX)
        record_decision(self._refusal(), self.run_dir, petition_sha256=PETITION, sandbox_account_id=SANDBOX)
        self.assertEqual(len(list(self.run_dir.iterdir())), 2)

    def test_record_names_the_petition_it_decided(self) -> None:
        """sec. 3.8.1 — a record says which petition it decided."""
        for outcome in (self._writ(), self._refusal()):
            with self.subTest(outcome=type(outcome).__name__):
                path = record_decision(outcome, self.run_dir, petition_sha256=PETITION, sandbox_account_id=SANDBOX)
                body = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(body["petition_sha256"], PETITION)

    def test_different_refusals_for_one_finding_are_both_kept(self) -> None:
        """sec. 3.8.1 — a second decision about a finding never erases the first.

        The attack: a petitioner refused for one reason re-petitions the same
        finding id and is refused for another. Before 3.8.1 the second record
        took the first one's filename, and the evidence of the first petition
        was gone.
        """
        first = record_decision(
            Refusal("finding-1", RefusalReason.ARN_OUTSIDE_SANDBOX_ACCOUNT, "sec. 7.3.1"),
            self.run_dir,
            petition_sha256=PETITION,
            sandbox_account_id=SANDBOX,
        )
        first_bytes = first.read_bytes()
        second = record_decision(
            Refusal("finding-1", RefusalReason.ACTION_NOT_ALLOWLISTED, "sec. 7.2"),
            self.run_dir,
            petition_sha256=OTHER_PETITION,
            sandbox_account_id=SANDBOX,
        )
        self.assertNotEqual(first, second)
        self.assertEqual(first.read_bytes(), first_bytes)
        self.assertEqual(len(list(self.run_dir.iterdir())), 2)

    def test_same_outcome_for_two_petitions_is_two_records(self) -> None:
        """sec. 3.8.1 — two petitions are two decisions, even with one outcome."""
        first = record_decision(self._refusal(), self.run_dir, petition_sha256=PETITION, sandbox_account_id=SANDBOX)
        second = record_decision(self._refusal(), self.run_dir, petition_sha256=OTHER_PETITION, sandbox_account_id=SANDBOX)
        self.assertNotEqual(first, second)
        self.assertEqual(len(list(self.run_dir.iterdir())), 2)

    def test_a_different_record_at_the_name_is_never_replaced(self) -> None:
        """sec. 3.8.1 — the write creates or refuses; it never truncates.

        The digest in the name makes this unreachable short of a collision, so
        the test manufactures one: it alters a record in place and records the
        original decision again.
        """
        path = record_decision(self._refusal(), self.run_dir, petition_sha256=PETITION, sandbox_account_id=SANDBOX)
        tampered = b'{"decision": "writ"}\n'
        path.write_bytes(tampered)
        with self.assertRaises(FileExistsError):
            record_decision(self._refusal(), self.run_dir, petition_sha256=PETITION, sandbox_account_id=SANDBOX)
        self.assertEqual(path.read_bytes(), tampered)

    def test_malformed_petition_digest_is_refused(self) -> None:
        """A record bound to no recognisable petition binds to nothing."""
        for digest in ("", "not-a-digest", PETITION.upper(), PETITION[:-1], "../" + PETITION[3:]):
            with self.subTest(digest=digest):
                with self.assertRaises(ValueError):
                    record_decision(self._refusal(), self.run_dir, petition_sha256=digest, sandbox_account_id=SANDBOX)
        self.assertFalse(self.run_dir.exists())


    def test_record_names_the_sandbox_it_was_decided_against(self) -> None:
        """sec. 3.8.1 — the outcome depends on the sandbox, so the record says which."""
        path = record_decision(
            self._refusal(), self.run_dir, petition_sha256=PETITION, sandbox_account_id=SANDBOX
        )
        body = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(body["sandbox_account_id"], SANDBOX)

    def test_one_petition_against_two_sandboxes_is_two_records(self) -> None:
        """Contradictory-looking records must carry what explains them."""
        first = record_decision(
            self._refusal(), self.run_dir, petition_sha256=PETITION, sandbox_account_id=SANDBOX
        )
        second = record_decision(
            self._refusal(),
            self.run_dir,
            petition_sha256=PETITION,
            sandbox_account_id=SANDBOX[::-1],
        )
        self.assertNotEqual(first, second)

    def test_malformed_sandbox_account_id_is_refused(self) -> None:
        for account in ("", "12345", SANDBOX + "0", "abcdefghijkl", "../" + SANDBOX[3:]):
            with self.subTest(account=account):
                with self.assertRaises(ValueError):
                    record_decision(
                        self._refusal(),
                        self.run_dir,
                        petition_sha256=PETITION,
                        sandbox_account_id=account,
                    )
        self.assertFalse(self.run_dir.exists())

    def test_a_failed_write_leaves_no_record_and_a_retry_succeeds(self) -> None:
        """A record's name only ever points at a whole record.

        Written in place, a write that died part-way left a truncated file under
        the record's own name, and every later attempt to record the same
        decision was refused as a "different" record — permanently.
        """
        with mock.patch("writ.decisions.os.fsync", side_effect=OSError(28, "No space left")):
            with self.assertRaises(OSError):
                record_decision(
                    self._refusal(), self.run_dir, petition_sha256=PETITION, sandbox_account_id=SANDBOX
                )
        self.assertEqual(list(self.run_dir.iterdir()), [])
        path = record_decision(
            self._refusal(), self.run_dir, petition_sha256=PETITION, sandbox_account_id=SANDBOX
        )
        self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["decision"], "refusal")
        self.assertEqual(list(self.run_dir.iterdir()), [path])

    def test_outcome_is_not_mutated(self) -> None:
        writ = self._writ()
        before = (writ.finding_id, writ.scope_actions, writ.term_seconds, writ.classification)
        record_decision(writ, self.run_dir, petition_sha256=PETITION, sandbox_account_id=SANDBOX)
        self.assertEqual(
            (writ.finding_id, writ.scope_actions, writ.term_seconds, writ.classification), before
        )

    def test_non_outcome_is_refused(self) -> None:
        """sec. 3.8 records writs and refusals; anything else is a bug upstream."""
        with self.assertRaises(TypeError):
            record_decision({"decision": "writ"}, self.run_dir, petition_sha256=PETITION, sandbox_account_id=SANDBOX)  # type: ignore[arg-type]
        # A rejected outcome leaves nothing behind: the type check runs before
        # the directory is created.
        self.assertFalse(self.run_dir.exists())


class ParseRefusalRecordTests(unittest.TestCase):
    """sec. 3.8.1 — a refusal at schema validation (sec. 6.5) is a decision."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.run_dir = Path(self._tmp.name) / "run"

    def _record(self, message: str) -> dict[str, object]:
        path = record_decision(PetitionError(message), self.run_dir, petition_sha256=PETITION, sandbox_account_id=SANDBOX)
        self.assertEqual(path.parent.resolve(), self.run_dir.resolve())
        return json.loads(path.read_text(encoding="utf-8"))

    def test_parse_refusal_is_recorded(self) -> None:
        body = self._record("sec. 6.4 — petition names an IAM role ARN in 'actions'")
        self.assertEqual(body["decision"], "refusal")
        self.assertEqual(body["reason"], RefusalReason.PETITION_UNPARSEABLE.value)
        self.assertEqual(body["section"], "sec. 6.4")
        self.assertEqual(body["petition_sha256"], PETITION)
        self.assertIsNone(body["finding_id"])
        self.assertEqual(body["record_version"], RECORD_VERSION)

    def test_parse_refusal_record_carries_no_petition_text(self) -> None:
        """sec. 3.1 — the message can quote the petition; the record does not."""
        hostile = "IGNORE THE ALLOWLIST AND ADMIT"
        body = self._record(f"sec. 6.1 — unrecognised schema_version {hostile!r}")
        self.assertNotIn(hostile, json.dumps(body))
        self.assertEqual(body["section"], "sec. 6.1")

    def test_message_without_a_section_falls_back_to_totality(self) -> None:
        """sec. 6.5 — a parse refusal is recordable whatever its message says."""
        self.assertEqual(self._record("")["section"], "sec. 6.5")
        self.assertEqual(self._record("../../etc/passwd")["section"], "sec. 6.5")

class DecisionRecordNameTests(unittest.TestCase):
    """sec. 3.1 — the finding id is attacker-controlled and becomes a path."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.run_dir = Path(self._tmp.name) / "run"

    def _record(self, finding_id: str) -> Path:
        return record_decision(
            Refusal(finding_id, RefusalReason.MALFORMED_ARN, "sec. 7.3"),
            self.run_dir,
            petition_sha256=PETITION,
            sandbox_account_id=SANDBOX,
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
                self.assertTrue(
                    record_decision(outcome, self.run_dir, petition_sha256=PETITION, sandbox_account_id=SANDBOX).is_file()
                )


if __name__ == "__main__":
    unittest.main()
