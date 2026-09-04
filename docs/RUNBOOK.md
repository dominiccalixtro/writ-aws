# Runbook

Operational procedures for writ-aws. See docs/IMPLEMENTATION_PLAN.md for the
governing contract; this file records how each procedure was actually
exercised, per sec. 4.3.3 and acceptance A0.4.

## Quash

Not yet exercised. Section 4.3 requires the SCP-based quash path to be
exercised at least once during Phase 0, with the result recorded here:
command run, timestamp, and confirmation that the broker role lost all
access (e.g. an `AccessDenied` on a call that succeeded before quash).

## Fixture capture

Not yet performed. Section 5 requires fixtures to be captured once from a
live sandbox account, then the sandbox destroyed. Record here: capture date,
which findings/plans/events were captured, and confirmation of `terraform
destroy` leaving no billable resource (acceptance A1.4).

## Phase 0 findings — STS scoping lab

Performed. This exercise **does not satisfy any A0 acceptance criterion**; it is
preparatory verification carried out before designing Phase 3 scoped issuance,
not Phase 0 completion. A0.1 through A0.5 all remain outstanding.

- **Date:** 2026-09-02
- **Account:** sandbox (<sandbox-account-id>)
- **Purpose:** verify STS `AssumeRole` intersection semantics before designing
  Phase 3 scoped issuance.
- **Method:** two throwaway IAM roles — narrow (three S3 public-access-block
  actions) and broad (`s3:*`) — two S3 buckets, and four CLI-executed tests.

### Results

- Session policy scoped to one bucket ARN: permitted on that bucket,
  `AccessDenied` on the other — **resource narrowing confirmed**.
- Session policy omitting an action the role held (`s3:ListAllMyBuckets`):
  denied — **action subtraction confirmed**.
- Session policy granting `ec2:*`, `iam:*`, `s3:*` against the narrow role: the
  `AssumeRole` call succeeded, but every call outside the role's three actions
  was denied — **escalation via session policy confirmed impossible**.
- Identical session policy against the broad role: `s3:ListBuckets` succeeded
  and `s3:DeleteBucket` would have succeeded — confirming **blast radius scales
  with capability-role breadth**.

### Operational finding — denial messages name the failing layer

AWS denial messages identify which side of the intersection rejected the call:

- `because no session policy allows...` — the writ was scoped too tightly, or
  the petition resource was mis-parsed.
- `because no identity-based policy allows...` — the capability role lacks the
  action, or the wrong role was selected.

Decision records should capture the **full denial string** rather than a
normalised `AccessDenied`; the distinction is lost by normalising.

### Incidental

Newly created S3 buckets returned all four public-access-block settings already
`true` (S3 default since April 2023). This weakens `s3:PutPublicAccessBlock` as
a first capability candidate — the remediation is less frequently needed on
modern buckets than on legacy ones.

**Cross-reference:** `docs/ADR-001-sts-scoping.md`.

### Lab teardown — pending operator action

The lab created four resources in the sandbox from the CLI. They are **not**
managed by Terraform, so `terraform destroy` will not remove them. Leaving them
creates untracked drift in an account A1.4 expects to be clean, and
`writ-lab-broad` grants `s3:*`.

```
IAM role   writ-lab-narrow  (inline policy: narrow)
IAM role   writ-lab-broad   (inline policy: broad)
S3 bucket  writ-lab-alpha-<sandbox-account-id>
S3 bucket  writ-lab-beta-<sandbox-account-id>
```

Deletions have **not** been run. The operator executes them:

```bash
# Set ACCT to the sandbox account ID before running.
ACCT=<sandbox-account-id>

# IAM roles — the inline policy must be deleted before the role
aws iam delete-role-policy --role-name writ-lab-narrow --policy-name narrow --profile writ-sandbox
aws iam delete-role --role-name writ-lab-narrow --profile writ-sandbox
aws iam delete-role-policy --role-name writ-lab-broad --policy-name broad --profile writ-sandbox
aws iam delete-role --role-name writ-lab-broad --profile writ-sandbox

# S3 buckets — must be empty before deletion
aws s3api delete-bucket --bucket writ-lab-alpha-$ACCT --profile writ-sandbox
aws s3api delete-bucket --bucket writ-lab-beta-$ACCT --profile writ-sandbox
```

Record the completion date here once run, and confirm no lab resource remains
(`aws iam list-roles`, `aws s3api list-buckets`).
