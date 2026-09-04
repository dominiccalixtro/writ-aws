"""sec. 6 — petition schema tests. Skeleton: each test below names the
invariant it will assert once writ.petition.parse_petition is implemented.
"""

from __future__ import annotations

import json
import unittest

from writ import petition
from writ.petition import PetitionError, parse_petition


def _valid_document() -> dict[str, object]:
    """The minimal schema-valid petition every adversarial case is derived from."""
    return {
        "schema_version": petition.SCHEMA_VERSION,
        "finding_id": "finding-0001",
        "actions": ["s3:PutBucketPublicAccessBlock"],
        "resource_arns": ["arn:aws:s3:::example-bucket"],
        "rationale": "Bucket permits public read.",
    }


def _encode(document: object) -> bytes:
    return json.dumps(document).encode("utf-8")


class PetitionSchemaTests(unittest.TestCase):
    @unittest.skip("sec. 7 not yet implemented — asserts on admit()")
    def test_rationale_field_does_not_affect_admission(self) -> None:
        """sec. 6.3 — two petitions differing only in rationale get identical decisions.

        When sec. 7 lands, both rationales must be text that *parses*: sec. 6.4
        still refuses a role ARN in a structural field, so the two petitions have
        to differ only in text the parser accepts. Rationale text naming an IAM
        principal is fine (see PetitionProhibitedStructureTests).
        """


class PetitionTotalityTests(unittest.TestCase):
    """sec. 6.5 — every input yields a Petition or a typed PetitionError.

    sec. 9.2: each case below is an input designed to defeat the rule above it.
    Several are accepted *silently* by a naive json.loads, which is why they are
    tested here rather than assumed.
    """

    def test_non_bytes_input_is_refused(self) -> None:
        """sec. 6.5 — the parser takes raw bytes; anything else refuses."""
        for raw in ("a string", 42, None, ["list"]):
            with self.subTest(raw=raw):
                with self.assertRaises(PetitionError):
                    parse_petition(raw)  # type: ignore[arg-type]

    def test_non_utf8_bytes_are_refused(self) -> None:
        """sec. 6.5 — a UnicodeDecodeError never escapes the parser."""
        with self.assertRaises(PetitionError):
            parse_petition(b"\xff\xfe" + _encode(_valid_document()))

    def test_deeply_nested_json_is_refused_without_recursion_error(self) -> None:
        """sec. 6.5 — depth is bounded before parsing, not by catching RecursionError."""
        with self.assertRaises(PetitionError):
            parse_petition(b"[" * 5000 + b"]" * 5000)

    def test_malformed_and_truncated_json_is_refused(self) -> None:
        """sec. 6.5 — a JSONDecodeError never escapes the parser."""
        for raw in (b'{"finding_id":', b"{", b"}{", b'{"a" "b"}', b"[1,]"):
            with self.subTest(raw=raw):
                with self.assertRaises(PetitionError):
                    parse_petition(raw)

    def test_non_object_top_level_is_refused(self) -> None:
        """sec. 6.1 — a petition is a JSON object; a scalar, list or null is not."""
        for raw in (b"42", b'"text"', b"null", b"true", b"[]", b"[1, 2]"):
            with self.subTest(raw=raw):
                with self.assertRaises(PetitionError):
                    parse_petition(raw)

    def test_empty_and_whitespace_input_is_refused(self) -> None:
        """sec. 6.5 — empty input is not a petition."""
        for raw in (b"", b"   ", b"\n\t "):
            with self.subTest(raw=raw):
                with self.assertRaises(PetitionError):
                    parse_petition(raw)

    def test_duplicate_top_level_key_is_refused_and_last_wins_did_not_occur(self) -> None:
        """sec. 6.5 — duplicate keys smuggle a value past human review.

        json.loads resolves this last-wins and reports nothing: a reviewer reading
        the raw petition sees the safe action while the parser would have taken the
        dangerous one. The parse must refuse rather than silently pick either.
        """
        raw = (
            b'{"schema_version": "' + petition.SCHEMA_VERSION.encode("utf-8") + b'",'
            b'"finding_id": "finding-0001",'
            b'"actions": ["s3:GetBucketPublicAccessBlock"],'
            b'"actions": ["iam:DeleteRole"],'
            b'"resource_arns": ["arn:aws:s3:::example-bucket"],'
            b'"rationale": "text"}'
        )
        # The vector is real: the stdlib parser accepts this and keeps the last value.
        self.assertEqual(json.loads(raw)["actions"], ["iam:DeleteRole"])
        with self.assertRaises(PetitionError):
            parse_petition(raw)

    def test_duplicate_nested_key_is_refused(self) -> None:
        """sec. 6.5 — the same vector one level down."""
        raw = b'{"schema_version": "x", "finding_id": {"a": 1, "a": 2}}'
        with self.assertRaises(PetitionError):
            parse_petition(raw)

    def test_non_json_constants_are_refused(self) -> None:
        """sec. 6.5 — json.loads accepts NaN/Infinity though JSON does not.

        Re-serializing such a petition emits output other parsers reject, which
        would break digest stability (sec. 7.8).
        """
        for literal in (b"NaN", b"Infinity", b"-Infinity"):
            with self.subTest(literal=literal):
                raw = b'{"schema_version": "x", "finding_id": ' + literal + b"}"
                # The vector is real: the stdlib parser accepts it.
                self.assertIn("finding_id", json.loads(raw))
                # The reason is asserted so a later check cannot mask a missing
                # parse_constant hook by refusing this input for its own reasons.
                with self.assertRaises(PetitionError) as caught:
                    parse_petition(raw)
                self.assertIn("sec. 6.5", str(caught.exception))

    def test_out_of_bounds_numbers_are_refused(self) -> None:
        """sec. 6.5 — numbers beyond practical bounds never reach a Petition."""
        for literal in (b"9" * 5000, b"1e400", b"-" + b"9" * 100):
            with self.subTest(literal=literal[:12]):
                raw = b'{"schema_version": "x", "finding_id": ' + literal + b"}"
                with self.assertRaises(PetitionError) as caught:
                    parse_petition(raw)
                self.assertIn("sec. 6.5", str(caught.exception))

    def test_oversized_input_is_refused_before_decoding(self) -> None:
        """sec. 6.5 — the size bound applies to bytes, before any decode."""
        raw = b'{"rationale": "' + b"x" * (petition.MAX_PETITION_BYTES + 1) + b'"}'
        with self.assertRaises(PetitionError) as caught:
            parse_petition(raw)
        self.assertIn("sec. 6.5", str(caught.exception))


class PetitionSchemaValidationTests(unittest.TestCase):
    """sec. 6.1, 6.2 — the schema is closed and versioned."""

    def test_valid_petition_parses(self) -> None:
        """sec. 6.2 — the baseline every adversarial case below mutates."""
        parsed = parse_petition(_encode(_valid_document()))
        self.assertEqual(parsed.finding_id, "finding-0001")
        self.assertEqual(parsed.actions, ("s3:PutBucketPublicAccessBlock",))
        self.assertEqual(parsed.resource_arns, ("arn:aws:s3:::example-bucket",))
        self.assertEqual(parsed.schema_version, petition.SCHEMA_VERSION)

    def test_unknown_top_level_key_is_refused_not_ignored(self) -> None:
        """sec. 6.1 — an unknown key refuses; it is never silently dropped."""
        for key in ("assume_role", "broker_instruction", "x"):
            with self.subTest(key=key):
                document = _valid_document()
                document[key] = "value"
                with self.assertRaises(PetitionError):
                    parse_petition(_encode(document))

    def test_absent_schema_version_is_refused(self) -> None:
        """sec. 6.1 — there is no 'assume latest' path."""
        document = _valid_document()
        del document["schema_version"]
        with self.assertRaises(PetitionError):
            parse_petition(_encode(document))

    def test_unrecognised_schema_version_is_refused(self) -> None:
        """sec. 6.1 — only the enumerated version parses."""
        for version in ("writ.petition/v2", "v1", "", None, 1):
            with self.subTest(version=version):
                document = _valid_document()
                document["schema_version"] = version
                with self.assertRaises(PetitionError):
                    parse_petition(_encode(document))

    def test_each_missing_required_field_is_refused(self) -> None:
        """sec. 6.2 — every mandatory field is mandatory on its own."""
        for field in ("schema_version", "finding_id", "resource_arns", "rationale"):
            with self.subTest(field=field):
                document = _valid_document()
                del document[field]
                with self.assertRaises(PetitionError):
                    parse_petition(_encode(document))

    def test_petition_without_an_action_set_is_refused(self) -> None:
        """sec. 6.2 — the proposed action set is mandatory in one form or the other."""
        document = _valid_document()
        del document["actions"]
        with self.assertRaises(PetitionError):
            parse_petition(_encode(document))

    def test_petition_declaring_both_action_forms_is_refused(self) -> None:
        """sec. 6.2 — AWS API actions or a Terraform diff, never both."""
        document = _valid_document()
        document["terraform_diff"] = 'resource "aws_s3_bucket" ...'
        with self.assertRaises(PetitionError):
            parse_petition(_encode(document))

    def test_terraform_diff_alone_supplies_the_action_set(self) -> None:
        """sec. 6.2 — a diff is the other legal form of the proposed action set."""
        document = _valid_document()
        del document["actions"]
        document["terraform_diff"] = 'resource "aws_s3_bucket" ...'
        parsed = parse_petition(_encode(document))
        self.assertEqual(parsed.actions, ())
        self.assertIsNotNone(parsed.terraform_diff)

    def test_wrong_typed_fields_are_refused(self) -> None:
        """sec. 6.2 — a field of the right name but the wrong type is not a field."""
        mutations = (
            ("finding_id", 1),
            ("finding_id", ""),
            ("actions", "s3:PutBucketPublicAccessBlock"),
            ("actions", []),
            ("actions", [1]),
            ("resource_arns", {}),
            ("resource_arns", [""]),
            ("rationale", ["text"]),
        )
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                document = _valid_document()
                document[field] = value
                with self.assertRaises(PetitionError):
                    parse_petition(_encode(document))


class PetitionProhibitedStructureTests(unittest.TestCase):
    """sec. 6.4 — credentials, role ARNs and policy documents refuse structurally.

    Detection is by key name and object shape only. The parser deliberately does
    not scan text for instruction-like content; see the writ.petition docstring.
    """

    def test_credential_shaped_key_is_refused(self) -> None:
        """sec. 6.4 — a petition has no legitimate field so named."""
        for key in (
            "aws_access_key_id",
            "AWS_SECRET_ACCESS_KEY",
            "SessionToken",
            "password",
            "private_key",
            "api-key",
            "credentials",
        ):
            with self.subTest(key=key):
                document = _valid_document()
                document["resource_arns"] = [{key: "value"}]
                with self.assertRaises(PetitionError):
                    parse_petition(_encode(document))

    def test_credential_shaped_key_nested_deeply_is_refused(self) -> None:
        """sec. 6.4 — the scan reaches any depth, not just the top level."""
        document = _valid_document()
        document["resource_arns"] = [{"a": {"b": {"c": {"secret_access_key": "AKIA"}}}}]
        with self.assertRaises(PetitionError):
            parse_petition(_encode(document))

    def test_role_arn_is_refused(self) -> None:
        """sec. 6.4 — the agent plane may not name a role for the broker to assume."""
        for arn in (
            "arn:aws:iam::123456789012:role/AdminRole",
            "arn:aws-us-gov:iam::123456789012:role/path/Role",
            "arn:aws:sts::123456789012:assumed-role/Role/session",
        ):
            with self.subTest(arn=arn):
                document = _valid_document()
                document["resource_arns"] = [arn]
                with self.assertRaises(PetitionError):
                    parse_petition(_encode(document))

    def test_role_arn_buried_several_levels_deep_is_refused(self) -> None:
        """sec. 6.4 — a petition valid but for one role ARN four levels down.

        Buried inside `resource_arns`, a structural field, so the narrowed scope
        of the scan does not exempt it.
        """
        document = _valid_document()
        document["resource_arns"] = [
            "arn:aws:s3:::example-bucket",
            {"detail": {"nested": {"deeper": ["arn:aws:iam::123456789012:role/Admin"]}}},
        ]
        with self.assertRaises(PetitionError) as caught:
            parse_petition(_encode(document))
        self.assertIn("sec. 6.4", str(caught.exception))

    def test_role_arn_embedded_in_a_structural_field_is_refused(self) -> None:
        """sec. 6.4 — an ARN inside a longer string in a structural field still refuses."""
        document = _valid_document()
        document["terraform_diff"] = "role = arn:aws:iam::123456789012:role/Admin"
        del document["actions"]
        with self.assertRaises(PetitionError) as caught:
            parse_petition(_encode(document))
        self.assertIn("sec. 6.4", str(caught.exception))

    def test_role_arn_in_the_rationale_parses(self) -> None:
        """sec. 6.4 — "role ARNs to assume" is functional, not lexical.

        sec. 7.6 anticipates IAM petitions and forces them to `human`. Such a
        petition naturally names the principal in its rationale, which sec. 6.3
        renders non-influential. Refusing it would push agents toward vaguer
        rationales, degrading the field humans read during review.
        """
        document = _valid_document()
        document["actions"] = ["iam:UpdateAccessKey"]
        document["rationale"] = (
            "Access key on arn:aws:iam::123456789012:role/Admin is unused; deactivate it."
        )
        parsed = parse_petition(_encode(document))
        self.assertIn("arn:aws:iam::123456789012:role/Admin", parsed.rationale)

    def test_credential_in_the_rationale_is_still_refused(self) -> None:
        """sec. 6.4 — credential detection is global; the rationale is not exempt."""
        document = _valid_document()
        document["rationale"] = {"aws_secret_access_key": "AKIAEXAMPLE"}
        with self.assertRaises(PetitionError) as caught:
            parse_petition(_encode(document))
        self.assertIn("sec. 6.4", str(caught.exception))

    def test_target_resource_arns_are_not_mistaken_for_role_arns(self) -> None:
        """sec. 6.4 — non-role ARNs are target resources, validated later (sec. 7.3)."""
        for arn in (
            "arn:aws:s3:::example-bucket",
            "arn:aws:ec2:us-east-1:123456789012:security-group/sg-1",
            "arn:aws:iam::123456789012:policy/SomePolicy",
        ):
            with self.subTest(arn=arn):
                document = _valid_document()
                document["resource_arns"] = [arn]
                self.assertEqual(parse_petition(_encode(document)).resource_arns, (arn,))

    def test_embedded_policy_document_is_refused(self) -> None:
        """sec. 6.4 — policy documents are not authored by the agent plane."""
        policies = (
            {"Version": "2012-10-17", "Statement": []},
            {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]},
            {"statement": {"Effect": "Allow"}},
        )
        for policy in policies:
            with self.subTest(policy=sorted(policy)):
                document = _valid_document()
                document["resource_arns"] = [policy]
                with self.assertRaises(PetitionError):
                    parse_petition(_encode(document))

    def test_policy_document_nested_deeply_is_refused(self) -> None:
        """sec. 6.4 — shape detection reaches any depth."""
        document = _valid_document()
        document["resource_arns"] = [
            {"a": {"b": {"policy": {"Version": "2012-10-17", "Statement": []}}}}
        ]
        with self.assertRaises(PetitionError):
            parse_petition(_encode(document))


class PetitionDeterminismTests(unittest.TestCase):
    """sec. 3.4 — parsing is a pure function of the input bytes."""

    def test_identical_input_parses_to_an_identical_petition(self) -> None:
        """sec. 3.4 — no clock, randomness, environment or filesystem is consulted."""
        raw = _encode(_valid_document())
        self.assertEqual(parse_petition(raw), parse_petition(raw))

    def test_identical_invalid_input_refuses_with_an_identical_reason(self) -> None:
        """sec. 3.4 — refusal reasons are stable, so decision records are too."""
        raw = _encode({**_valid_document(), "unexpected": "value"})
        reasons = []
        for _ in range(2):
            with self.assertRaises(PetitionError) as caught:
                parse_petition(raw)
            reasons.append(str(caught.exception))
        self.assertEqual(reasons[0], reasons[1])


if __name__ == "__main__":
    unittest.main()
