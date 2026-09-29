# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## The contract governs

`docs/IMPLEMENTATION_PLAN.md` is binding. It uses SHALL / MUST NOT language and
numbered acceptance criteria, and it wins over the README, over this file, and
over any inference from the code. Read the relevant section before changing
anything in `writ/`, and cite it in docstrings the way existing modules do
(`sec. 7.3`, `invariant I6`) — that citation style is how the code is reviewed
against the contract.

`writ/` is implemented through Phase 2 (sec. 6-7, 3.8.1): a petition is parsed,
admitted or refused, and recorded, and no code path reaches AWS. Phase 0 is
applied (A0.1-A0.4 satisfied, A0.5 partial; `docs/RUNBOOK.md`). Phase 1 tooling
is ready but nothing has been captured. Of Phase 2's acceptance, A2.2 and A2.3
wait on those captures, and A2.4 is verified by human review.

Five tests skip, and each names what it waits on; do not unskip one by
inventing behavior:

- `tests/test_admission.py`, 1 test — the sec. 7.3 tag check, deferred to
  Phase 3 (sec. 7.3.2) because it needs an AWS read.
- `tests/test_injection_corpus.py`, 4 tests — the fixture-driven corpus run
  (sec. 9.3, A2.2, A2.3 as amended). They skip until a finding is committed
  under `tests/fixtures/findings/` (Phase 1, sec. 5); from then on a missing or
  malformed fixture is an error, not a skip.

## Commands

```bash
python -m unittest discover -s tests -v        # full suite
python -m unittest tests.test_admission -v     # one module
python -m unittest tests.test_admission.AdmissionAllowlistTests.test_action_outside_allowlist_is_refused
python -m pip install -e .                     # installs the `writ` console script
writ --petition <file> --sandbox-account-id <12 digits> [--run-dir .runs]   # admit or refuse one petition
python -m tools.redact_fixture --account <real>=123456789012 <raw> <fixture>   # redact a capture (sec. 5.4)
```

`writ` prints the decision record it just persisted. Exit codes: 0 writ, 1
refusal (parse refusals included, sec. 3.8.1), 2 no decision (unreadable
petition file, or record not written; argparse usage errors also exit 2).
`--finding` is a hidden alias for `--petition` (A2.3). The sandbox account ID is
an operator input, never read from the petition (sec. 7.3.1).

`tools.redact_fixture` runs on the operator's machine between capture and
commit. Raw captures go in gitignored `.capture/`; only its output is committed,
under `tests/fixtures/`. It refuses to write (exit 1) while any 12-digit
sequence remains that is not an allowed placeholder; exit 2 is bad input.

No third-party test dependency and no test runner beyond stdlib `unittest`
(sec. 9.1). No runtime dependencies at all — `pyproject.toml` declares
`dependencies = []` and Phases 0–2 must keep it that way (no `boto3`).

Tests must pass with **no network and no AWS credentials in the environment**
(sec. 5.5); `tests/test_offline.py` fails the run if `AWS_ACCESS_KEY_ID` and
friends are set. A test that needs either is a contract violation, not a
configuration problem.

## Architecture

One directional pipeline, split across five small modules in `writ/`:

```
raw bytes ──parse_petition──▶ Petition ──admit──▶ Writ | Refusal ──record_decision──▶ .runs/
 (petition.py)                          (admission.py)  (writs.py)      (decisions.py)
```

- `petition.py` — parsing is **total** (sec. 6.5): any input, including non-UTF-8
  bytes and adversarially nested JSON, either yields a `Petition` or raises
  `PetitionError`. Bounded (64 KiB, 32 levels); duplicate keys refused. Unknown
  top-level keys, credential-shaped keys, and role ARNs or policy documents in
  the structural fields are rejected *here*, not downstream (sec. 6.1, 6.4).
  Broker-directed instructions have no field to live in (closed schema); there
  is deliberately no content scanner, and none should be added (module docstring).
- `admission.py` — the only place a `Petition` may become a `Writ` or `Refusal`.
  Deterministic, deny-by-default, no model call ever (I2). Checks run in a fixed
  order: allowlist (sec. 7.1-7.2) → account scope (sec. 7.3.1; the tag check is
  deferred, 7.3.2; an ARN with no account field, such as S3's, is refused,
  7.3.3) → terraform plan gate (sec. 7.4), after which any diff petition is
  refused (7.4.1) → blast-radius band (sec. 7.5-7.6). It returns a `Refusal`
  with a typed `RefusalReason` for bad petitions; it does not raise. The sandbox
  account ID is an argument, never a petition field. `ACTION_BANDS` is the one
  table (sec. 7.5) and `ALLOWED_ACTIONS` derives from it; today it holds one
  action, `ec2:RevokeSecurityGroupIngress`, banded `auto`. `DELETABLE_RESOURCE_TYPES`
  is empty, so every planned delete refuses (sec. 7.4).
- `writs.py` — construction only. `MAX_TERM_SECONDS = 900` is a ceiling, never
  configurable upward (I7); 900 is also the sole legal term (sec. 7.7), so
  `term_seconds` is not a constructor argument. Scope may only *narrow* from the
  petition (sec. 3.6); in Phase 2 it is the petition's own actions and ARNs, and
  the intersection with the capability role's permissions is Phase 3.
- `decisions.py` — every outcome (writ, refusal, or parse refusal) is persisted
  before any next step (sec. 3.8). `RECORD_VERSION` is 2. A record is bound to
  `petition_sha256` (SHA-256 of the petition's raw bytes) and
  `sandbox_account_id`, and carries no timestamp. The filename carries a digest
  of the record's own bytes, and a record never replaces a different one: it is
  written to a temp file and `os.link`ed into place, and a different record
  already at the name raises `FileExistsError` (sec. 3.8.1). Write with
  `newline=""` so digests stay stable across platforms (sec. 7.8). A parse
  refusal is recorded with the digest and the sec. clause only, never the
  petition text (sec. 3.8.1).
- `cli.py` — petition in, the persisted decision record out. Never a network
  call. The record is written before anything is printed.

Beside the pipeline, not part of it:

- `tools/redact_fixture.py` — the sec. 5.4 redactor. Stdlib only, offline. It
  imports `ACCOUNT_ID_PATTERN` and `ALLOWED_ACCOUNT_PLACEHOLDERS` from
  `tests/test_redaction.py`, so the tool and the test cannot disagree.
- `terraform/bootstrap/` — the Phase 0 broker identity (sec. 4), applied.
  Not exercised by the suite. Its state is local and gitignored: do not
  validate an alternative var file in that directory, because a plan against
  placeholder accounts proposes rewriting the live quash SCP (`docs/RUNBOOK.md`,
  A0.2). Details in its README.
- `terraform/capture/` — the Phase 1 capture module (sec. 5): drafted, not yet
  applied. It creates deliberately insecure resources for one capture window and
  is destroyed straight after (sec. 5.1); procedure and teardown checks are in
  its README. Applying it is a live AWS action.
- `tests/fixtures/` — a README and `injection/corpus.json`, the sec. 9.3.1
  injection corpus. The corpus is authored, not captured: its petitions take
  every identifier from the finding they answer, so it carries none of its own.
  The captured findings, plans, and CloudTrail event are still pending
  (Phase 1); the paths the corpus refers to are listed in the fixtures README.

## Constraints that shape every change

- **No AWS write capability anywhere.** Phases 0–2 end at a printed, unexecuted
  writ (I8, A2.4 — verified by human review, not by an assertion). Do not add
  an SDK client, a credential path, or a "just for testing" execution branch.
- **Findings and the `rationale` field are untrusted data, never instructions**
  (sec. 3.1, 6.3). Text from a finding must not reach a decision as anything but
  data; two petitions differing only in rationale must decide identically.
- **`ALWAYS_HUMAN_PREFIXES` (iam, cloudtrail, kms, organizations) is not
  configurable** (sec. 7.6). Anything touching those classifies `human`, full stop.
- **The allowlist contains no wildcards** (sec. 7.1), and blast-radius banding is
  data, not code branches (sec. 7.5).
- **A refusal is terminal** — no automatic retry, repair, or negotiation (sec. 3.7).
- **Adversarial test first.** A new admission rule does not merge without a test
  proving the corresponding unsafe input is rejected (sec. 9.2, 9.5). Each
  invariant I1–I8 needs at least one passing adversarial test (A2.1).
- **Phases 3–5 are out of contract** (sec. 12): scoped STS issuance, serving a
  writ, CloudTrail reconciliation. Do not implement them because they seem next.
- **`sentinelcloud-engineering-loop` is out of scope** (sec. 1.2). Reuse the
  design discipline; copy source deliberately with in-file attribution; never
  import across repositories.

## Working agreement

- **Decisions: go with the recommendation.** When a choice has to be made, lay
  out the options briefly, give one recommendation, and proceed with it — the
  operator has pre-approved going with the recommendation. Say which option was
  taken, and why, in the commit message. A decision that changes the contract
  is made by amending `docs/IMPLEMENTATION_PLAN.md` with a numbered sub-clause
  (the way 7.3.1 was added), in the same change. This covers design and
  implementation choices only: live AWS actions, anything that spends money,
  force-pushes, and deleting branches or history still need an explicit yes.
- **Authorship.** Commit as `Angel Dominic Kynnt Calixtro <dominic.calixtro@gmail.com>`.
  No `Co-Authored-By` or `Claude-Session` trailers, and no "Generated with
  Claude Code" lines, in commits or pull request descriptions.
