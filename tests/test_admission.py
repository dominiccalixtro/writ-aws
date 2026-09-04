"""sec. 7 and sec. 8 (invariants I1-I8) — admission policy tests. Skeleton:
each test names the invariant it will assert once writ.admission.admit is
implemented. sec. 9.2/9.5: every admission rule ships with an adversarial
test proving the unsafe input is rejected — these are that suite's spine.
"""

from __future__ import annotations

import unittest

from writ import writs


class AdmissionAllowlistTests(unittest.TestCase):
    @unittest.skip("sec. 7 not yet implemented")
    def test_action_outside_allowlist_is_refused(self) -> None:
        """invariant I4."""

    @unittest.skip("sec. 7 not yet implemented")
    def test_wildcard_action_in_allowlist_is_rejected_at_definition_time(self) -> None:
        """sec. 7.1 — the allowlist itself may never contain a wildcard."""


class AdmissionResourceScopeTests(unittest.TestCase):
    @unittest.skip("sec. 7 not yet implemented")
    def test_arn_outside_sandbox_account_is_refused(self) -> None:
        """invariant I5."""

    @unittest.skip("sec. 7 not yet implemented")
    def test_arn_missing_sandbox_tag_is_refused(self) -> None:
        """sec. 7.3."""

    @unittest.skip("sec. 7 not yet implemented")
    def test_one_bad_arn_refuses_entire_petition(self) -> None:
        """sec. 7.3 — no partial admission."""


class AdmissionClassificationTests(unittest.TestCase):
    @unittest.skip("sec. 7 not yet implemented")
    def test_iam_touching_petition_is_never_auto(self) -> None:
        """invariant I6."""

    @unittest.skip("sec. 7 not yet implemented")
    def test_cloudtrail_touching_petition_is_never_auto(self) -> None:
        """invariant I6."""

    @unittest.skip("sec. 7 not yet implemented")
    def test_writ_term_never_exceeds_900_seconds(self) -> None:
        """invariant I7."""


class WritConstructionTests(unittest.TestCase):
    """sec. 7.7 — 900 is the sole legal term, so no other is constructible."""

    def test_writ_cannot_be_constructed_with_a_non_compliant_term(self) -> None:
        """sec. 7.7 — adversarial: a sub-900 term is unserveable at Phase 3.

        A term below 900 would satisfy I7's ceiling yet be rejected by the STS
        DurationSeconds minimum. The constructor must refuse the value outright
        rather than carry it into a serialized writ.
        """
        for term in (0, 1, 300, 899, 901):
            with self.subTest(term=term):
                with self.assertRaises(TypeError):
                    writs.Writ(
                        finding_id="finding-1",
                        scope_actions=("s3:PutBucketPublicAccessBlock",),
                        scope_resource_arns=("arn:aws:s3:::bucket",),
                        term_seconds=term,
                        classification="auto",
                    )

        # sec. 7.8: the term is still carried on the writ it could not override.
        writ = writs.Writ(
            finding_id="finding-1",
            scope_actions=("s3:PutBucketPublicAccessBlock",),
            scope_resource_arns=("arn:aws:s3:::bucket",),
            classification="auto",
        )
        self.assertEqual(writ.term_seconds, 900)


class AdmissionDeterminismTests(unittest.TestCase):
    @unittest.skip("sec. 7 not yet implemented")
    def test_admission_does_not_invoke_a_model(self) -> None:
        """invariant I2."""

    @unittest.skip("sec. 7 not yet implemented")
    def test_same_petition_always_yields_same_decision(self) -> None:
        """invariant I3 corollary — determinism, no hidden state."""


class InjectionCorpusTests(unittest.TestCase):
    """sec. 9.3 — findings carrying instructions directed at the reader."""

    @unittest.skip("sec. 9.3 fixtures not yet captured (Phase 1)")
    def test_finding_requesting_cloudtrail_disable_is_refused_or_human(self) -> None:
        """A finding whose remediation text asks to disable CloudTrail."""

    @unittest.skip("sec. 9.3 fixtures not yet captured (Phase 1)")
    def test_finding_requesting_unrelated_iam_attachment_is_refused_or_human(self) -> None:
        """A finding whose remediation text asks to attach a policy elsewhere."""


if __name__ == "__main__":
    unittest.main()
