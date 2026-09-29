"""sec. 6, 7 and acceptance A2.3 — the command line end to end.

A2.3: running the CLI prints a writ or a typed refusal and performs no network
call, "proven by a test that fails on any socket construction". That proof is
test_no_socket_is_constructed below.
"""

from __future__ import annotations

import hashlib
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from writ import petition as petition_module
from writ.cli import EXIT_ADMITTED, EXIT_INPUT_ERROR, EXIT_REFUSED, main

SANDBOX = "123456789012"
ALLOWED_ACTION = "ec2:RevokeSecurityGroupIngress"
SANDBOX_ARN = f"arn:aws:ec2:ap-southeast-1:{SANDBOX}:security-group/sg-0123456789abcdef0"


class CliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.run_dir = self.tmp / "runs"

    def _write_petition(self, **overrides: object) -> Path:
        document: dict[str, object] = {
            "schema_version": petition_module.SCHEMA_VERSION,
            "finding_id": "finding-0001",
            "actions": [ALLOWED_ACTION],
            "resource_arns": [SANDBOX_ARN],
            "rationale": "Security group permits 0.0.0.0/0 on port 22.",
        }
        document.update(overrides)
        path = self.tmp / "petition.json"
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def _run(self, *argv: str) -> tuple[int, str, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def _base_args(self, path: Path) -> tuple[str, ...]:
        return (
            "--petition", str(path),
            "--sandbox-account-id", SANDBOX,
            "--run-dir", str(self.run_dir),
        )

    def test_admitted_petition_prints_a_writ(self) -> None:
        code, out, _ = self._run(*self._base_args(self._write_petition()))
        self.assertEqual(code, EXIT_ADMITTED)
        body = json.loads(out)
        self.assertEqual(body["decision"], "writ")
        self.assertEqual(body["term_seconds"], 900)

    def test_refused_petition_prints_a_typed_refusal(self) -> None:
        path = self._write_petition(actions=["s3:DeleteBucket"])
        code, out, _ = self._run(*self._base_args(path))
        self.assertEqual(code, EXIT_REFUSED)
        body = json.loads(out)
        self.assertEqual(body["decision"], "refusal")
        self.assertEqual(body["reason"], "action_not_allowlisted")
        self.assertEqual(body["section"], "sec. 7.2")

    def test_printed_output_is_the_recorded_bytes(self) -> None:
        """sec. 3.8 — what the operator reads is what was persisted."""
        code, out, _ = self._run(*self._base_args(self._write_petition()))
        self.assertEqual(code, EXIT_ADMITTED)
        records = list(self.run_dir.iterdir())
        self.assertEqual(len(records), 1)
        self.assertEqual(out, records[0].read_text(encoding="utf-8"))

    def test_decision_is_recorded_even_when_refused(self) -> None:
        """sec. 3.8 — 'admission and refusal alike'."""
        self._run(*self._base_args(self._write_petition(actions=["s3:DeleteBucket"])))
        self.assertEqual(len(list(self.run_dir.iterdir())), 1)

    def test_unparseable_petition_is_a_recorded_refusal_not_a_traceback(self) -> None:
        """sec. 6.5 — parsing is total; sec. 3.8.1 — and its refusal is recorded."""
        path = self.tmp / "petition.json"
        path.write_text("{not json", encoding="utf-8")
        code, out, err = self._run(*self._base_args(path))
        self.assertEqual(code, EXIT_REFUSED)
        self.assertIn("refused at parse", err)
        body = json.loads(out)
        self.assertEqual(body["decision"], "refusal")
        self.assertEqual(body["reason"], "petition_unparseable")
        self.assertEqual(len(list(self.run_dir.iterdir())), 1)

    def test_non_utf8_petition_does_not_raise(self) -> None:
        path = self.tmp / "petition.json"
        path.write_bytes(b"\xff\xfe\x00garbage")
        code, _, err = self._run(*self._base_args(path))
        self.assertEqual(code, EXIT_REFUSED)
        self.assertIn("writ:", err)

    def test_prohibited_petition_leaves_a_record(self) -> None:
        """sec. 3.8.1 — the refusals most worth auditing happen at parse.

        A petition naming a role for the broker to assume (sec. 6.4) never
        reaches admit(); before 3.8.1 it left no trace in the run directory.
        """
        role_arn = f"arn:aws:iam::{SANDBOX}:role/attacker"
        path = self._write_petition(resource_arns=[role_arn])
        code, out, _ = self._run(*self._base_args(path))
        self.assertEqual(code, EXIT_REFUSED)
        body = json.loads(out)
        self.assertEqual(body["section"], "sec. 6.4")
        self.assertNotIn(role_arn, out)

    def test_record_names_the_petition_bytes(self) -> None:
        """sec. 3.8.1 — the digest is of the exact bytes the broker read."""
        path = self._write_petition()
        _, out, _ = self._run(*self._base_args(path))
        expected = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(json.loads(out)["petition_sha256"], expected)

    def test_second_petition_for_a_finding_does_not_erase_the_first(self) -> None:
        """sec. 3.8.1 — end to end: two refusals, one finding, two records."""
        first = self._write_petition(resource_arns=[SANDBOX_ARN.replace(SANDBOX, SANDBOX[::-1])])
        _, first_out, _ = self._run(*self._base_args(first))
        second = self._write_petition(actions=["iam:AttachRolePolicy"])
        _, second_out, _ = self._run(*self._base_args(second))
        self.assertEqual(json.loads(first_out)["reason"], "arn_outside_sandbox_account")
        self.assertEqual(json.loads(second_out)["reason"], "action_not_allowlisted")
        recorded = sorted(p.read_text(encoding="utf-8") for p in self.run_dir.iterdir())
        self.assertEqual(recorded, sorted([first_out, second_out]))

    def test_unwritable_record_is_an_input_error_and_prints_no_decision(self) -> None:
        """sec. 3.8 — an unrecorded decision is never reported as one."""
        blocker = self.tmp / "not-a-dir"
        blocker.write_text("", encoding="utf-8")
        code, out, err = self._run(
            "--petition", str(self._write_petition()),
            "--sandbox-account-id", SANDBOX,
            "--run-dir", str(blocker),
        )
        self.assertEqual(code, EXIT_INPUT_ERROR)
        self.assertEqual(out, "")
        self.assertIn("not recorded", err)

    def test_missing_file_is_reported(self) -> None:
        code, _, err = self._run(*self._base_args(self.tmp / "absent.json"))
        self.assertEqual(code, EXIT_INPUT_ERROR)
        self.assertIn("cannot read", err)

    def test_sandbox_account_is_not_taken_from_the_petition(self) -> None:
        """sec. 7.3 — a petition naming its own sandbox would decide its own check."""
        path = self._write_petition()
        code, out, _ = self._run(
            "--petition", str(path),
            "--sandbox-account-id", SANDBOX[::-1],
            "--run-dir", str(self.run_dir),
        )
        self.assertEqual(code, EXIT_REFUSED)
        self.assertEqual(json.loads(out)["reason"], "arn_outside_sandbox_account")

    def test_diff_petition_is_a_recorded_refusal_not_a_traceback(self) -> None:
        """sec. 7.4.1, 3.8 — before 7.4.1 a gate-passing diff crashed the CLI.

        The traceback exited 1, the same code as a refusal, with no record.
        """
        plan = (
            '{"type":"planned_change","change":{"resource":'
            '{"resource_type":"aws_security_group"},"action":"update"}}\n'
        )
        path = self.tmp / "petition.json"
        document = {
            "schema_version": petition_module.SCHEMA_VERSION,
            "finding_id": "finding-0001",
            "terraform_diff": plan,
            "resource_arns": [SANDBOX_ARN],
            "rationale": "remove the open ingress rule",
        }
        path.write_text(json.dumps(document), encoding="utf-8")
        code, out, _ = self._run(*self._base_args(path))
        self.assertEqual(code, EXIT_REFUSED)
        body = json.loads(out)
        self.assertEqual(body["reason"], "plan_scope_undefined")
        self.assertEqual(len(list(self.run_dir.iterdir())), 1)

    def test_record_names_the_sandbox(self) -> None:
        _, out, _ = self._run(*self._base_args(self._write_petition()))
        self.assertEqual(json.loads(out)["sandbox_account_id"], SANDBOX)

    def test_malformed_sandbox_account_id_is_rejected_before_any_decision(self) -> None:
        """An operator typo is not a sandbox; nothing is decided or recorded."""
        for account in ("12345", SANDBOX + "0", "", "\u0661" * 12):
            with self.subTest(account=account):
                with self.assertRaises(SystemExit):
                    with redirect_stderr(io.StringIO()):
                        main([
                            "--petition", str(self._write_petition()),
                            "--sandbox-account-id", account,
                            "--run-dir", str(self.run_dir),
                        ])
        self.assertFalse(self.run_dir.exists())

    def test_parse_refusal_is_not_reported_before_it_is_recorded(self) -> None:
        """sec. 3.8 — nothing, stderr included, precedes persistence."""
        path = self.tmp / "petition.json"
        path.write_text("{not json", encoding="utf-8")
        blocker = self.tmp / "not-a-dir"
        blocker.write_text("", encoding="utf-8")
        code, out, err = self._run(
            "--petition", str(path),
            "--sandbox-account-id", SANDBOX,
            "--run-dir", str(blocker),
        )
        self.assertEqual(code, EXIT_INPUT_ERROR)
        self.assertEqual(out, "")
        self.assertNotIn("refused at parse", err)

    def test_sandbox_account_id_is_required(self) -> None:
        with self.assertRaises(SystemExit):
            with redirect_stderr(io.StringIO()):
                main(["--petition", str(self._write_petition())])

    def test_finding_alias_still_works(self) -> None:
        path = self._write_petition()
        code, _, _ = self._run(
            "--finding", str(path),
            "--sandbox-account-id", SANDBOX,
            "--run-dir", str(self.run_dir),
        )
        self.assertEqual(code, EXIT_ADMITTED)

    def test_petition_and_finding_are_mutually_exclusive(self) -> None:
        path = self._write_petition()
        with self.assertRaises(SystemExit):
            with redirect_stderr(io.StringIO()):
                main([
                    "--petition", str(path),
                    "--finding", str(path),
                    "--sandbox-account-id", SANDBOX,
                ])

    def test_no_socket_is_constructed(self) -> None:
        """acceptance A2.3, invariant I8 — the run reaches no network at all."""
        path = self._write_petition()
        with mock.patch("socket.socket", side_effect=AssertionError("CLI opened a socket")):
            code, _, _ = self._run(*self._base_args(path))
        self.assertEqual(code, EXIT_ADMITTED)

        refused = self._write_petition(actions=["s3:DeleteBucket"])
        with mock.patch("socket.socket", side_effect=AssertionError("CLI opened a socket")):
            code, _, _ = self._run(*self._base_args(refused))
        self.assertEqual(code, EXIT_REFUSED)

        unparseable = self.tmp / "unparseable.json"
        unparseable.write_bytes(b"{not json")
        with mock.patch("socket.socket", side_effect=AssertionError("CLI opened a socket")):
            code, _, _ = self._run(*self._base_args(unparseable))
        self.assertEqual(code, EXIT_REFUSED)


if __name__ == "__main__":
    unittest.main()
