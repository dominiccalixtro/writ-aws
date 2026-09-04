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

## Layout

- `writ/` — the broker: petition schema, admission policy, writ construction,
  decision records, CLI. Pure Python, no AWS SDK calls in Phases 0-2.
- `terraform/bootstrap/` — sandbox-account broker role, permissions boundary,
  SCP quash path. Requires a live AWS Organization; not yet implemented.
- `tests/` — adversarial by default (sec. 9.2): every admission rule ships
  with a test proving the unsafe input is rejected. Runs fully offline
  (sec. 5.5) — no network, no AWS credentials.
- `tests/fixtures/` — redacted findings and Terraform plans captured once
  from a live sandbox, then replayed forever. Empty until Phase 1.
- `docs/IMPLEMENTATION_PLAN.md` — the binding contract. SHALL/MUST NOT
  language, numbered acceptance criteria. Where this README and the plan
  disagree, the plan wins.
- `docs/RUNBOOK.md` — records of procedures actually exercised (quash,
  fixture capture).

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
