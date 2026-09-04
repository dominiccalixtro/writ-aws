# Runbook

Operational procedures for writ-aws. See docs/IMPLEMENTATION_PLAN.md for the
governing contract; this file records how each procedure was actually
exercised, per sec. 4.3.3 and acceptance A0.4.

## Quash

Not yet exercised. Section 4.3 requires the SCP-based quash path to be
exercised at least once during Phase 0, with the result recorded here:
command run, timestamp, and confirmation that the broker role lost all
access (e.g. an `AccessDenied` on a call that succeeded before quash).

### Pre-flight before attempting A0.4

The quash SCP was created successfully by `terraform apply`, but creating an
SCP and attaching one are different operations. Attachment requires the
`SERVICE_CONTROL_POLICY` policy type to be enabled on the organization root,
which is not automatic even in all-features mode. This was not verified before
apply. Check first:

```bash
aws organizations list-roots --profile writ-management
```

Look for `SERVICE_CONTROL_POLICY` with status `ENABLED` in `PolicyTypes`. If
absent:

```bash
aws organizations enable-policy-type \
  --root-id r-zg8s \
  --policy-type SERVICE_CONTROL_POLICY \
  --profile writ-management
```

Free. Without it, the `attach-policy` step of A0.4 fails.

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

## Organization structure change

- **Date:** 2026-09-04
- **Cost:** free.

Manual prerequisite, not managed in Terraform. `aws_organizations_account` would
place the sandbox account in Terraform state, and `terraform destroy` would then
attempt to close it — a 90-day irreversible operation that would violate sec.
4.4.4's requirement that modules be cleanly destroyable.

The sandbox OU is created by Terraform. Moving the account into it is manual and
one-time:

```bash
ACCT=<sandbox-account-id>
OU=ou-zg8s-xkkyz4wh

aws organizations move-account \
  --account-id $ACCT \
  --source-parent-id r-zg8s \
  --destination-parent-id $OU \
  --profile writ-management
```

Verified: `dc-sandbox` is the sole account in `writ-sandbox`
(`ou-zg8s-xkkyz4wh`). The management account remains directly under Root, which
is correct — SCPs do not apply to it in any case (sec. 4.1.3).

## A0.1 — broker role exists in the sandbox account

- **Date:** 2026-09-04
- **Status:** satisfied
- **Cost:** free. IAM roles, policies, OUs, and SCPs are unbilled.

`terraform apply` on `terraform/bootstrap/` created 4 resources:

| Resource | Identifier |
|---|---|
| Broker role | `arn:aws:iam::<sandbox-account-id>:role/writ-broker` |
| Permissions boundary policy | `arn:aws:iam::<sandbox-account-id>:policy/writ-broker-boundary` |
| Sandbox OU | `ou-zg8s-xkkyz4wh` |
| Quash SCP (detached) | `p-mphj9kb6` |

The broker role exists only in the sandbox account. No broker role exists in the
management account, per sec. 4.1.3.

State at rest in Phases 0–2 — effective permissions are zero, enforced three
independent ways:

- **Trust policy:** a single `Deny` on `sts:AssumeRole` for `Principal: *`. No
  principal can assume the role.
- **Permissions boundary:** contains no `Allow` statement, because
  `capability_role_arns` is empty. A boundary is an intersection, so the ceiling
  is zero.
- **Identity policy:** not created. The `aws_iam_role_policy` resource is gated
  on `count = length(var.capability_role_arns) > 0 ? 1 : 0`.

Any one of the three would be sufficient alone.

## A0.3 — sec. 4.2.3 denies verified by simulation

- **Date:** 2026-09-04
- **Status:** satisfied, with two recorded limitations
- **Cost:** free. `simulate-principal-policy` is unbilled.

### Interpretation applied

A0.3's wording accepts `implicitDeny` **or** `explicitDeny`. Section 4.2.4
requires the denies to be expressed as explicit `Deny`, not as absence of
`Allow`. Under sec. 1.5 (where requirements conflict, the stricter constraint
wins), `explicitDeny` was required throughout.

This is not pedantry. A deny statement with a typo'd action name, a wrong
resource ARN, or a condition that never fires resolves to `implicitDeny` —
indistinguishable from a policy that was never written. A0.3's literal wording
would accept such a policy.

### Results

**21 actions are declared across the three deny statements in `broker.tf`. These
were verified via 22 simulation calls.** The counts differ because
`organizations:*` and `account:*` are single wildcard entries in the policy but
cannot be simulated as wildcards; each was probed with concrete actions instead.

Every call returned `explicitDeny`.

**Escalation (sec. 4.2.3)** — 8 declared actions, 9 simulation calls:
`iam:CreateUser`, `iam:CreateAccessKey`, `iam:AttachUserPolicy`,
`iam:PutUserPolicy`, `iam:DeleteRolePermissionsBoundary`,
`iam:PutRolePermissionsBoundary`, and — as concrete probes against the two
wildcards — `organizations:LeaveOrganization`, `organizations:CreateAccount`,
`account:PutAlternateContact`.

**Evidence integrity, CloudTrail** — 4 actions: `cloudtrail:StopLogging`,
`cloudtrail:DeleteTrail`, `cloudtrail:UpdateTrail`,
`cloudtrail:PutEventSelectors`.

**Evidence integrity, trail log bucket** — 9 actions, simulated with
`--resource-arns` against the placeholder bucket ARN. Bucket-level and
object-level ARNs were passed separately, since the `/*` suffix is required for
object-level statements to match:

- Bucket-level: `s3:DeleteBucket`, `s3:PutLifecycleConfiguration`,
  `s3:PutBucketVersioning`, `s3:PutBucketPolicy`, `s3:DeleteBucketPolicy`
- Object-level: `s3:DeleteObject`, `s3:DeleteObjectVersion`,
  `s3:PutObjectRetention`, `s3:PutObjectLegalHold`

Sample output for `iam:CreateUser`, confirming a statement actually matched:

```json
"EvalDecision": "explicitDeny",
"MatchedStatements": [
    {
        "SourcePolicyId": "writ-broker-boundary",
        "SourcePolicyType": "Permissions Boundary Policy"
    }
],
"PermissionsBoundaryDecisionDetail": {
    "AllowedByPermissionsBoundary": false
}
```

The non-empty `MatchedStatements` array is what distinguishes a working deny
from an absent one.

### Negative control

Two actions not named in any deny statement:

| Action | Decision |
|---|---|
| `s3:GetObject` | `implicitDeny` |
| `ec2:DescribeInstances` | `implicitDeny` |

This is the check that makes the result meaningful. Had these also returned
`explicitDeny`, the denies would be over-broad. Had the sec. 4.2.3 actions
returned `implicitDeny`, none of the statements would be matching and sec. 4.2.4
would be unmet despite the policy appearing correct.

### Limitation 1 — wildcard coverage is unverifiable by simulation

`simulate-principal-policy` requires concrete action names; a wildcard cannot be
passed as an action. The denies on `organizations:*` and `account:*` were
therefore confirmed via three concrete actions, which proves the wildcards match
those actions. It does not prove they match every action in either service
namespace.

This is a limitation of the tool, not of the policy. Complete verification of a
wildcard deny is not achievable by this method.

### Limitation 2 — boundary-escape deny does not yet exist

Section 4.2.3's third group denies `sts:AssumeRole` on any principal other than
those enumerated. This is implemented as a `NotResource` deny inside a `dynamic`
block gated on `capability_role_arns` being non-empty.

With the list empty (correct for Phases 0–2), **no statement is emitted**, so
there is nothing to simulate. The protection in this state comes from absence of
`Allow` rather than explicit `Deny` — weaker than sec. 4.2.4 prefers, but
unavoidable: a `NotResource` deny excluding an empty set denies everything,
which would permanently block Phase 3.

Recorded as a Phase 3 dependency. This deny must be verified when
`capability_role_arns` is first populated.

## A0.5 — budget alarms

- **Date:** 2026-09-04
- **Status:** partially satisfied

### Budgets confirmed to exist

| Budget | Scope | Threshold | Alert type |
|---|---|---|---|
| My Monthly Cost Budget | Org-wide | $10 | Actual |
| My Zero-Spend Budget | Org-wide | $1 | Actual |
| Sandbox Zero Budget | **Filter incorrect — see below** | $1 | Actual |

All notify the operator's primary personal email address, verified as monitored.

Section 4.4.1 is satisfied: budget alarms exist before any billable resource has
been created.

### Not confirmed to fire

Month-to-date actual spend is $0.045 in the management account and $0.00 in the
sandbox — below every threshold. An artificial trigger is not possible: a budget
threshold cannot be lowered below existing spend when that spend is effectively
zero.

Deliberately incurring a charge to satisfy this criterion was rejected as
contradicting sec. 4.4's cost discipline.

**Firing will be confirmed during Phase 1 fixture capture**, which is the first
real spend in this project. That is a stronger test than an artificial one:
enabling AWS Config and Security Hub exercises the alarm against exactly the
spend it exists to catch.

### Open defect — sandbox budget filter

"Sandbox Zero Budget" was created in the management account but its
linked-account filter was set to `<management-account-id>` rather than
`<sandbox-account-id>`. The account picker defaults to the signed-in account,
and the default was accepted.

The budget name said "Sandbox"; the filter did not. Confirmed by a forecast of
$0.876, matching the org-wide budget rather than the sandbox's $0 history.

**Cannot currently be corrected.** The linked-account picker is populated from
billing data, and the sandbox account has generated no billing records since
creation, so it does not yet appear as a selectable value. Expected to resolve
within roughly 24 hours of account creation, or once the account generates its
first charge.

**Action required before Phase 1 Stage 2:** correct the filter and verify via
`aws budgets describe-budgets`, confirming `CostFilters` contains
`LinkedAccount: ["<sandbox-account-id>"]`. The alarm must be correct **before**
detection services are enabled, per sec. 4.4.1.

Note: `CostFilters` was absent from CLI output even when a filter was configured
in the console. Absence of that field is not reliable evidence of an unfiltered
budget; the console is authoritative.
