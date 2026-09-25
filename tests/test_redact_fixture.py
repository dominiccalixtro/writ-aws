"""sec. 5.4 — the capture-side redactor (tools/redact_fixture.py).

Adversarial by default (sec. 9.2): each case is an identifier a real capture
carries, and the assertion is that it does not survive to the committed file.
Every "real" value below is assembled at runtime, never written out, for the
reason tests/test_redaction.py gives: a literal would itself fail that scan.
"""

from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from tests.test_redaction import ALLOWED_ACCOUNT_PLACEHOLDERS
from tools.redact_fixture import RedactionError, main, redact, residue

PLACEHOLDER = "123456789012"
REAL = "4" * 12
OTHER_REAL = "7" * 12


class RedactTests(unittest.TestCase):
    def test_named_account_is_replaced_everywhere(self) -> None:
        text = (
            f'{{"AwsAccountId": "{REAL}", '
            f'"Id": "arn:aws:ec2:ap-southeast-1:{REAL}:security-group/sg-0abc"}}'
        )
        out = redact(text, {REAL: PLACEHOLDER}, {})
        self.assertNotIn(REAL, out)
        self.assertEqual(out.count(PLACEHOLDER), 2)
        self.assertEqual(residue(out), set())

    def test_unnamed_account_is_left_as_residue(self) -> None:
        """The tool does not guess: an account it was not told about is reported."""
        out = redact(f"{REAL} and {OTHER_REAL}", {REAL: PLACEHOLDER}, {})
        self.assertEqual(residue(out), {OTHER_REAL})

    def test_placeholder_must_be_on_the_redaction_allowlist(self) -> None:
        self.assertIn(PLACEHOLDER, ALLOWED_ACCOUNT_PLACEHOLDERS)
        with self.assertRaises(RedactionError):
            redact(REAL, {REAL: OTHER_REAL}, {})

    def test_account_must_be_twelve_digits(self) -> None:
        with self.assertRaises(RedactionError):
            redact("x", {"12345": PLACEHOLDER}, {})

    def test_longer_digit_run_is_not_mistaken_for_the_account(self) -> None:
        """An account id inside a longer number is not that account id."""
        longer = REAL + "9"
        self.assertEqual(redact(longer, {REAL: PLACEHOLDER}, {}), longer)

    def test_aws_key_and_unique_ids_are_replaced(self) -> None:
        for prefix in ("AKIA", "ASIA", "AROA", "AIDA", "ABIA", "ACCA"):
            with self.subTest(prefix=prefix):
                real_id = prefix + "Q7" * 8
                out = redact(f'"accessKeyId": "{real_id}"', {}, {})
                self.assertNotIn(real_id, out)
                self.assertIn(prefix + "EXAMPLE", out)

    def test_routable_addresses_are_replaced_and_stay_distinct(self) -> None:
        first, second = "8.8.4.4", "1.1.1.1"
        out = redact(f"{first} {second} {first}", {}, {})
        self.assertNotIn(first, out)
        self.assertNotIn(second, out)
        self.assertEqual(out, "192.0.2.1 192.0.2.2 192.0.2.1")

    def test_routable_ipv6_is_replaced(self) -> None:
        out = redact('"sourceIPAddress": "2606:4700:4700::1111"', {}, {})
        self.assertNotIn("2606:4700", out)
        self.assertIn("2001:db8::1", out)

    def test_open_cidr_and_private_addresses_are_kept(self) -> None:
        """0.0.0.0/0 is the security-group finding; private space names no one."""
        text = '"CidrIp": "0.0.0.0/0", "PrivateIpAddress": "172.31.5.10", "10.0.0.1"'
        self.assertEqual(redact(text, {}, {}), text)

    def test_email_is_replaced(self) -> None:
        out = redact("assumed-role/AWSReservedSSO_Admin/someone.real@mail.example.org", {}, {})
        self.assertNotIn("someone.real", out)
        self.assertIn("operator@example.com", out)

    def test_literals_replace_longest_first(self) -> None:
        out = redact("AdministratorAccess_abc123def", {}, {"abc123": "X", "abc123def": "HASH"})
        self.assertEqual(out, "AdministratorAccess_HASH")

    def test_empty_literal_is_refused(self) -> None:
        with self.assertRaises(RedactionError):
            redact("text", {}, {"": "x"})

    def test_plan_json_structure_survives(self) -> None:
        """Keys such as "@level" are not emails; timestamps are not addresses."""
        line = (
            '{"@level":"info","@timestamp":"2026-09-25T22:08:09.351390Z",'
            '"change":{"action":"update"},"type":"planned_change"}'
        )
        self.assertEqual(redact(line, {}, {}), line)

    def test_arns_with_empty_fields_survive(self) -> None:
        """Every ASFF finding carries ARNs with "::" in them; none may change."""
        for arn in (
            "arn:aws:s3:::writ-capture-public-20260925",
            '"ProductArn": "arn:aws:securityhub:ap-southeast-1::product/aws/securityhub"',
            "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole",
            "arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0",
            "arn:aws:iam::aws:policy/AdministratorAccess",
        ):
            with self.subTest(arn=arn):
                self.assertEqual(redact(arn, {}, {}), arn)

    def test_address_ending_a_sentence_is_replaced(self) -> None:
        out = redact("Request came from 8.8.8.8. It was denied.", {}, {})
        self.assertEqual(out, "Request came from 192.0.2.1. It was denied.")
        out = redact("Source 2606:4700:4700::1111. Denied.", {}, {})
        self.assertEqual(out, "Source 2001:db8::1. Denied.")

    def test_dotted_runs_that_are_not_addresses_survive(self) -> None:
        for text in ("1.2.3.4.5", "v2023.6.20241010.0", "ami-2023.8.8.8.8x"):
            with self.subTest(text=text):
                self.assertEqual(redact(text, {}, {}), text)

    def test_s3_canonical_user_id_is_replaced(self) -> None:
        canonical = ("3f" * 32)
        out = redact(f'"OwnerId": "{canonical}"', {}, {})
        self.assertNotIn(canonical, out)
        self.assertEqual(residue(out), set())

    def test_identity_store_id_is_replaced(self) -> None:
        out = redact('"identityStoreArn": "arn:aws:identitystore::x:identitystore/d-9f7e6d5c4b"', {}, {})
        self.assertNotIn("d-9f7e6d5c4b", out)
        self.assertIn("d-0000000000", out)

    def test_redaction_is_idempotent(self) -> None:
        text = f"{REAL} 8.8.4.4 AKIA{'Q7' * 8} a@b.example.com"
        once = redact(text, {REAL: PLACEHOLDER}, {})
        self.assertEqual(redact(once, {REAL: PLACEHOLDER}, {}), once)


class RedactCliTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.source = self.tmp / "raw.json"
        self.destination = self.tmp / "out" / "fixture.json"

    def _run(self, *argv: str) -> int:
        with redirect_stderr(io.StringIO()):
            return main([str(self.source), str(self.destination), *argv])

    def test_clean_redaction_writes_the_fixture(self) -> None:
        self.source.write_text(f'{{"AwsAccountId": "{REAL}"}}\r\n', encoding="utf-8", newline="")
        self.assertEqual(self._run("--account", f"{REAL}={PLACEHOLDER}"), 0)
        self.assertEqual(
            self.destination.read_bytes(), f'{{"AwsAccountId": "{PLACEHOLDER}"}}\r\n'.encode()
        )

    def test_residue_writes_nothing(self) -> None:
        """sec. 5.4 — the check runs before the file exists, not after commit."""
        self.source.write_text(f"{REAL} {OTHER_REAL}", encoding="utf-8")
        self.assertEqual(self._run("--account", f"{REAL}={PLACEHOLDER}"), 1)
        self.assertFalse(self.destination.exists())

    def test_bad_arguments_write_nothing(self) -> None:
        self.source.write_text(REAL, encoding="utf-8")
        self.assertEqual(self._run("--account", REAL), 2)
        self.assertEqual(self._run("--account", f"{REAL}={OTHER_REAL}"), 2)
        self.assertFalse(self.destination.exists())

    def test_non_utf8_source_writes_nothing(self) -> None:
        self.source.write_bytes(b"\xff\xfe" + REAL.encode())
        self.assertEqual(self._run("--account", f"{REAL}={PLACEHOLDER}"), 2)
        self.assertFalse(self.destination.exists())


if __name__ == "__main__":
    unittest.main()
