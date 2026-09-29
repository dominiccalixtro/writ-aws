# writ-aws

A deny-by-default admission broker for AI-proposed AWS remediations. The
agent plane petitions; only the broker issues.

```
ASFF finding (untrusted)
      │
      ▼
[agent plane] ── no credentials, no AWS egress ──▶ petition (unsigned)
      │
      ▼
[broker: admission] ── deterministic, no model calls ──▶ writ | refusal
```

The agent that reads a security finding and proposes a fix never holds an
AWS credential. It emits a **petition** — unsigned, carrying no authority.
The **broker** is the only component with IAM, and it admits a petition into
a **writ** — scoped, expiring, narrower than both the request and the
broker's own permissions — only if the petition survives a deterministic
allowlist, a resource-scope check, and a blast-radius classification. Nothing
touching IAM or CloudTrail can ever auto-admit.

## Status

Phases 0-2 only (see `docs/IMPLEMENTATION_PLAN.md`): account boundary,
fixture capture, and petition admission ending at a **printed, unexecuted**
writ. No code path in this repository serves a writ against AWS yet —
that's Phase 3, out of contract until the plan is extended.

- **Phase 0** — applied to a live sandbox. A0.1-A0.4 are satisfied; A0.5
  (budget alarms confirmed to fire) is partial. Records: `docs/RUNBOOK.md`.
- **Phase 1** — nothing captured yet. The capture module is drafted, not
  applied, and the redaction tool is ready. The authored injection corpus is
  committed.
- **Phase 2** — implemented: petition parsing, admission, writ construction,
  decision records, CLI. Terraform-diff petitions are refused (sec. 7.4.1) and
  the sec. 7.3 tag check is deferred to Phase 3 (sec. 7.3.2). Acceptance is
  pending: A2.2 and A2.3 need the Phase 1 fixtures, and A2.4 is human review.

## Layout

- `writ/` — the broker: petition schema, admission policy, writ construction,
  decision records, CLI. Pure Python, no AWS SDK calls in Phases 0-2.
- `terraform/bootstrap/` — sandbox-account broker role, permissions boundary,
  sandbox OU, and the detached SCP quash path (sec. 4). Implemented and applied
  (`docs/RUNBOOK.md`); planning it needs a live AWS Organization, and no test
  runs it. See its README.
- `terraform/capture/` — the Phase 1 capture module: the four finding targets
  (deliberately insecure) and the detection services that evaluate them, for one
  capture window, destroyed straight after (sec. 5.1). Drafted, not yet applied;
  procedure in its README.
- `tools/` — `redact_fixture.py`, which redacts a raw capture before it is
  committed as a fixture (sec. 5.4). Raw captures go in gitignored `.capture/`.
- `tests/` — adversarial by default (sec. 9.2): every admission rule ships
  with a test proving the unsafe input is rejected. Runs fully offline
  (sec. 5.5) — no network, no AWS credentials.
- `tests/fixtures/` — holds the authored injection corpus
  (`injection/corpus.json`, sec. 9.3.1). Redacted findings, Terraform plans and
  a CloudTrail event are to be captured once from a live sandbox, then replayed
  forever; not yet captured (Phase 1).
- `docs/IMPLEMENTATION_PLAN.md` — the binding contract. SHALL/MUST NOT
  language, numbered acceptance criteria. Where this README and the plan
  disagree, the plan wins.
- `docs/RUNBOOK.md` — records of procedures actually exercised (Phase 0
  acceptance results, quash). Its fixture-capture record is still to be written.

## Relationship to sentinelcloud-engineering-loop

Separate program, separate threat model. That repository never holds cloud
credentials and never will; this one exists specifically to govern the
moment an agent's output could reach AWS. Design discipline (immutable
plans, fail-closed health checks, adversarial tests, untrusted-input framing)
is deliberately reused — source is not shared between the two repositories.

## Running tests

```bash
python -m unittest discover -s tests -v
```

No AWS account, credentials, or network access required or permitted
(sec. 5.5) — a test that needs either is a contract violation.
