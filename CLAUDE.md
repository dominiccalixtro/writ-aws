# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## The contract governs

`docs/IMPLEMENTATION_PLAN.md` is binding. It uses SHALL / MUST NOT language and
numbered acceptance criteria, and it wins over the README, over this file, and
over any inference from the code. Read the relevant section before changing
anything in `writ/`, and cite it in docstrings the way existing modules do
(`sec. 7.3`, `invariant I6`) — that citation style is how the code is reviewed
against the contract.

The repository is currently a **skeleton**: every function in `writ/` raises
`NotImplementedError` with the section it owes, and 17 of 19 tests are
`@unittest.skip`. Filling one in means implementing the contract section named
in its skip reason, not inventing behavior.

## Commands

```bash
python -m unittest discover -s tests -v        # full suite
python -m unittest tests.test_admission -v     # one module
python -m unittest tests.test_admission.AdmissionAllowlistTests.test_action_outside_allowlist_is_refused
python -m pip install -e .                     # installs the `writ` console script
writ --finding tests/fixtures/<name>.json      # CLI; exits 2 until sec. 6-7 land
```

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

- `petition.py` — parsing is **total**: any input, including non-UTF-8 bytes and
  adversarially nested JSON, either yields a `Petition` or raises `PetitionError`.
  Unknown top-level keys, embedded credentials, role ARNs, or broker-directed
  instructions are rejected *here*, not downstream (sec. 6.4).
- `admission.py` — the only place a `Petition` may become a `Writ` or `Refusal`.
  Deterministic, deny-by-default, no model call ever (I2). Checks run in a fixed
  order: allowlist → resource scope → terraform plan gate → blast-radius
  classification. It returns `Refusal` for bad petitions; it does not raise.
- `writs.py` — construction only. `MAX_TERM_SECONDS = 900` is a ceiling, never
  configurable upward (I7). Scope may only *narrow* from the petition (sec. 3.6).
- `decisions.py` — every outcome, admitted or refused, is persisted before any
  next step. Write with `newline=""` so digests stay stable across platforms
  (sec. 7.8).
- `cli.py` — fixture in, printed writ or refusal out. Never a network call.

`terraform/bootstrap/` and `tests/fixtures/` are deliberately empty. Bootstrap
needs a live AWS Organization to plan against; fixtures require a live sandbox
account to capture from and are then replayed forever. Neither is created
casually, and neither is exercised by the suite.

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
