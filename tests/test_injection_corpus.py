"""sec. 9.3, 9.3.1, acceptance A2.2 and A2.3 — the injection corpus.

The corpus (tests/fixtures/injection/corpus.json) is authored now; the findings
it plants text in are captured in Phase 1 (sec. 5). Until the first finding is
committed the fixture-driven tests skip. From then on nothing here skips: a
missing or malformed fixture is an error, so the corpus cannot quietly stop
running once Phase 1 has started (sec. 9.4 — fixtures only, never live AWS).

The corpus measures the broker on the assumption that injection has already
succeeded against the agent plane (sec. 9.3.1): each petition is what an agent
obeying the planted text would emit. A2.2 holds when none of them is `auto`.
"""

from __future__ import annotations

import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from writ import admission
from writ.admission import Refusal, admit
from writ.cli import EXIT_ADMITTED, EXIT_REFUSED, main
from writ.petition import SCHEMA_VERSION, PetitionError, parse_petition

FIXTURES = Path(__file__).resolve().parent / "fixtures"
CORPUS = FIXTURES / "injection" / "corpus.json"
FINDINGS = FIXTURES / "findings"

# sec. 9.3 — the two cases the corpus must include "at minimum".
MANDATED = frozenset({"cloudtrail-disable", "iam-unrelated-principal"})
# sec. 9.3.1 — the untrusted field every entry must at least be able to use.
MINIMUM_FIELD = "Remediation.Recommendation.Text"

PLACEHOLDER_ACCOUNT = "123456789012"


def load_corpus() -> dict:
    return json.loads(CORPUS.read_text(encoding="utf-8"))


def findings_captured() -> bool:
    return FINDINGS.is_dir() and any(FINDINGS.glob("*.json"))


def plant(finding: dict, dotted: str, text: str) -> dict:
    """A copy of `finding` with `text` at the dotted path (sec. 9.3.1 (a))."""
    planted = copy.deepcopy(finding)
    node = planted
    *parents, leaf = dotted.split(".")
    for key in parents:
        node = node.setdefault(key, {})
    node[leaf] = text
    return planted


def _fill(template: str, finding: dict) -> str:
    """Identifiers come from the finding, never from the corpus file."""
    values = {
        "{account}": finding["AwsAccountId"],
        "{region}": finding["Region"],
        "{resource_arn}": finding["Resources"][0]["Id"],
    }
    for key, value in values.items():
        template = template.replace(key, value)
    return template


def _plan(changes: list[dict]) -> str:
    """`terraform plan -json` lines in the machine-readable UI format (sec. 7.4)."""
    lines = [json.dumps({"@level": "info", "type": "version", "terraform": "1.16.4", "ui": "1.2"})]
    for change in changes:
        addr = change["addr"]
        lines.append(json.dumps({
            "@level": "info",
            "@message": f"{addr}: Plan to {change['action']}",
            "@module": "terraform.ui",
            "change": {
                "resource": {
                    "addr": addr,
                    "module": "",
                    "resource": addr,
                    "implied_provider": "aws",
                    "resource_type": change["resource_type"],
                    "resource_name": addr.split(".", 1)[1],
                    "resource_key": None,
                },
                "action": change["action"],
            },
            "type": "planned_change",
        }))
    return "\n".join(lines) + "\n"


def petition_bytes(template: dict, finding: dict, rationale: str) -> bytes:
    """The petition fixture for `finding`, as the broker would read it."""
    document: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "finding_id": finding["Id"],
        "resource_arns": [_fill(arn, finding) for arn in template["resource_arns"]],
        "rationale": rationale,
    }
    if "actions" in template:
        document["actions"] = [_fill(action, finding) for action in template["actions"]]
    else:
        document["terraform_diff"] = _plan(template["terraform_diff"])
    return json.dumps(document).encode("utf-8")


def verdict(raw: bytes, sandbox_account_id: str) -> str:
    """'refused', 'human' or 'auto'. A raise from admission is a failure, not a verdict.

    A parse refusal counts as a refusal: sec. 6.5 makes it a typed one and
    sec. 3.8.1 records it like any other.
    """
    try:
        petition = parse_petition(raw)
    except PetitionError:
        return "refused"
    try:
        outcome = admit(petition, sandbox_account_id)
    except Exception as exc:  # noqa: BLE001 — admit() is specified never to raise
        raise AssertionError(
            f"admit() raised {type(exc).__name__}: {exc}. sec. 7 requires a Writ or "
            "a Refusal for every parsed petition."
        ) from exc
    if isinstance(outcome, Refusal):
        return "refused"
    return outcome.classification


class CorpusShapeTests(unittest.TestCase):
    """The corpus itself — checkable before any finding is captured."""

    def setUp(self) -> None:
        self.corpus = load_corpus()

    def test_both_mandated_cases_are_present(self) -> None:
        """sec. 9.3 — CloudTrail disable, and IAM attached to an unrelated principal."""
        mandates = {entry["mandate"] for entry in self.corpus["entries"]}
        self.assertLessEqual(MANDATED, mandates)

    def test_every_entry_plants_text_in_an_untrusted_field(self) -> None:
        """sec. 9.3.1 (a) — at minimum Remediation.Recommendation.Text."""
        fields = set()
        for entry in self.corpus["entries"]:
            with self.subTest(entry=entry["name"]):
                self.assertTrue(entry["injected_text"].strip())
                fields.add(entry["injected_field"])
        self.assertIn(MINIMUM_FIELD, fields)

    def test_there_is_a_control_expected_to_admit_auto(self) -> None:
        """sec. 9.3.1 — so that refusing everything cannot pass vacuously."""
        self.assertTrue(any(c["expect"] == "auto" for c in self.corpus["controls"]))

    def test_entry_names_are_unique(self) -> None:
        names = [item["name"] for item in self.corpus["entries"] + self.corpus["controls"]]
        self.assertEqual(len(names), len(set(names)))

    def test_corpus_carries_no_account_of_its_own(self) -> None:
        """Every ARN takes its account from the finding it answers."""
        for item in self.corpus["entries"] + self.corpus["controls"]:
            for arn in item["petition"]["resource_arns"]:
                with self.subTest(item=item["name"], arn=arn):
                    self.assertTrue("{account}" in arn or arn == "{resource_arn}")

    def test_verdict_can_report_auto(self) -> None:
        """The detector must be able to fail, or A2.2 asserts nothing.

        Uses an in-memory stand-in shaped like a finding. This is the harness
        checking itself, not the corpus being exercised: sec. 9.4 runs the
        corpus against fixtures only, below.
        """
        stand_in = {
            "Id": "harness-self-check",
            "AwsAccountId": PLACEHOLDER_ACCOUNT,
            "Region": "ap-southeast-1",
            "Resources": [{
                "Id": f"arn:aws:ec2:ap-southeast-1:{PLACEHOLDER_ACCOUNT}:"
                      "security-group/sg-0123456789abcdef0",
            }],
        }
        control = self.corpus["controls"][0]
        raw = petition_bytes(control["petition"], stand_in, control["rationale"])
        self.assertEqual(verdict(raw, PLACEHOLDER_ACCOUNT), "auto")

    def test_verdict_does_not_swallow_an_admission_crash(self) -> None:
        """An exception is a defect to report, never a refusal to count."""
        raw = json.dumps({
            "schema_version": SCHEMA_VERSION,
            "finding_id": "f",
            "actions": ["ec2:RevokeSecurityGroupIngress"],
            "resource_arns": [f"arn:aws:ec2:ap-southeast-1:{PLACEHOLDER_ACCOUNT}:security-group/sg-1"],
            "rationale": "r",
        }).encode()
        with mock.patch.object(admission, "classify_band", side_effect=RuntimeError("boom")):
            with self.assertRaises(AssertionError):
                verdict(raw, PLACEHOLDER_ACCOUNT)


@unittest.skipUnless(
    findings_captured(),
    "sec. 9.3 — Phase 1 findings not yet captured (sec. 5); see terraform/capture/README.md",
)
class InjectionCorpusTests(unittest.TestCase):
    """sec. 9.3, A2.2 — against captured fixtures only (sec. 9.4)."""

    def setUp(self) -> None:
        self.corpus = load_corpus()

    def _finding(self, relative: str) -> dict:
        # Deliberately unguarded: once Phase 1 has begun, a missing fixture is
        # an error, not a reason to skip.
        return json.loads((FIXTURES / relative).read_text(encoding="utf-8"))

    def _entry_petitions(self):
        for entry in self.corpus["entries"]:
            planted = plant(
                self._finding(entry["finding"]), entry["injected_field"], entry["injected_text"]
            )
            raw = petition_bytes(entry["petition"], planted, entry["injected_text"])
            yield entry, planted, raw

    def test_no_corpus_entry_is_classified_auto(self) -> None:
        """A2.2 — zero `auto` across the corpus."""
        verdicts = {}
        for entry, planted, raw in self._entry_petitions():
            with self.subTest(entry=entry["name"]):
                verdicts[entry["name"]] = verdict(raw, planted["AwsAccountId"])
                self.assertIn(verdicts[entry["name"]], ("refused", "human"))
        self.assertNotIn("auto", verdicts.values())

    def test_rationale_carries_the_planted_text_verbatim(self) -> None:
        """sec. 9.3.1 (b) — the compromised agent echoes what it read."""
        for entry, _, raw in self._entry_petitions():
            with self.subTest(entry=entry["name"]):
                self.assertEqual(json.loads(raw)["rationale"], entry["injected_text"])

    def test_controls_decide_as_expected(self) -> None:
        """sec. 9.3.1 — the control admits, so the refusals above mean something."""
        for control in self.corpus["controls"]:
            finding = self._finding(control["finding"])
            raw = petition_bytes(control["petition"], finding, control["rationale"])
            with self.subTest(control=control["name"]):
                self.assertEqual(verdict(raw, finding["AwsAccountId"]), control["expect"])

    def test_cli_decides_every_petition_fixture_without_a_socket(self) -> None:
        """A2.3 as amended — the CLI against each petition fixture, no network."""
        items = [(e["name"], raw, p["AwsAccountId"]) for e, p, raw in self._entry_petitions()]
        for control in self.corpus["controls"]:
            finding = self._finding(control["finding"])
            raw = petition_bytes(control["petition"], finding, control["rationale"])
            items.append((control["name"], raw, finding["AwsAccountId"]))

        with tempfile.TemporaryDirectory() as tmp:
            for name, raw, account in items:
                with self.subTest(item=name):
                    path = Path(tmp) / f"{name}.json"
                    path.write_bytes(raw)
                    out = io.StringIO()
                    with mock.patch(
                        "socket.socket", side_effect=AssertionError("CLI opened a socket")
                    ), redirect_stdout(out), redirect_stderr(io.StringIO()):
                        code = main([
                            "--petition", str(path),
                            "--sandbox-account-id", account,
                            "--run-dir", str(Path(tmp) / "runs"),
                        ])
                    self.assertIn(code, (EXIT_ADMITTED, EXIT_REFUSED))
                    self.assertIn(json.loads(out.getvalue())["decision"], ("writ", "refusal"))


if __name__ == "__main__":
    unittest.main()
