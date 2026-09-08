# Runbook

Operational procedures for writ-aws. See docs/IMPLEMENTATION_PLAN.md for the
governing contract; this file records how each procedure was actually
exercised, per sec. 4.3.3 and acceptance A0.4.

## Quash

Exercised 2026-09-04. Section 4.3 requires the SCP-based quash path to be
exercised at least once during Phase 0, with the result recorded here:
command run, timestamp, and confirmation that the broker role lost all
access (e.g. an `AccessDenied` on a call that succeeded before quash). The
record is under **A0.4 — quash exercised** below.

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

Free. Without it, the `attach-policy` step of A0.4 fails. Confirmed
`ENABLED` on root `r-zg8s` before the A0.4 exercise.

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

### Lab teardown — complete

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

Deletions were run 2026-09-09. Commands kept for reference:

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

Completed 2026-09-09. `writ-lab-narrow` and `writ-lab-broad` were deleted with
their inline policies, and the `writ-lab-alpha-*` and `writ-lab-beta-*` buckets
were deleted. Verified by `aws iam list-roles` and `aws s3 ls`, both returning
no `writ-lab-*` resource.

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

## A0.2 — fresh-clone plan

- **Date:** 2026-09-04
- **Status:** satisfied
- **Cost:** free.

### Interpretation applied

A0.2 requires `terraform plan` to be "clean from a fresh clone." With state and
tfvars both gitignored, a fresh clone has neither, so plan necessarily reports
all resources as to-be-created rather than "no changes."

The reading applied: **plan runs without error given a valid tfvars file** —
every `.tf` parses, every variable type-checks, all policy JSON is constructed,
and the provider resolves from the committed lock file. It is a
structural-validity criterion, not a drift-detection one.

### Results

Fresh clone of `origin/main` into a temporary directory, real tfvars copied in:

- `terraform init` — resolved `hashicorp/aws v6.62.0` from
  `.terraform.lock.hcl`, not the latest available 6.x. This is what tracking the
  lock file buys: the fresh clone plans against the same provider the module was
  validated with.
- `terraform plan` — `4 to add, 0 to change, 0 to destroy`. No errors, no
  warnings.

The temporary clone and the copied tfvars were deleted afterwards.

### Two defects this run surfaced

**1. Uncommitted Terraform.** The first attempt emitted:

```
Warning: Value for undeclared variable
The root module does not declare a variable named "enable_quash_test_permission"
but a value was found in file "terraform.tfvars".
```

The A0.4 gate existed in the working tree but had never been committed. The
module in git could neither reproduce nor explain the exercise that had just
been run. Terraform treats undeclared variables in tfvars as a warning rather
than an error, so nothing failed loudly.

Worth generalising: reverting a tfvars value is not the same as committing the
`.tf` changes that made it meaningful.

**2. Broken `terraform.tfvars.example`.** The example file omitted several
declared variables and assigned `capability_role_arns = ""` where a
`list(string)` is required. Any fresh clone using the example — its only
purpose — would have failed on a type error.

This went unnoticed because the A0.2 run copied the operator's *real* tfvars
rather than the example. The test skipped the file it was meant to validate.

Both were fixed and committed before the run recorded above.

### Note on a dangerous pattern

While validating the corrected example, `terraform plan -var-file=...` was run
inside the live working directory. Terraform read the existing state, compared
it against placeholder account IDs, and proposed rewriting the live quash SCP to
reference `arn:aws:iam::123456789012:role/writ-broker` — pointing the kill
switch at a role in an account that does not exist, while leaving it looking
correctly configured.

Not applied. Recorded because Terraform gives no warning in this situation; the
diff appears as an ordinary in-place update. **Validating alternative variable
files requires a directory with no state**, not a `-var-file` override in the
live one.

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

## A0.4 — quash exercised

- **Date:** 2026-09-04
- **Status:** satisfied
- **Cost:** free. IAM, STS, SCPs, and `ListAllMyBuckets` are all unbilled.

### Pre-flight

`SERVICE_CONTROL_POLICY` confirmed `ENABLED` on root `r-zg8s` before starting,
per the procedure under Quash above. Creating an SCP and attaching one are
different operations; attachment requires the policy type to be enabled, which
is not automatic even in all-features mode. This was not verified before the
original `terraform apply`, and the SCP creation succeeding gave no signal
either way.

### Why a temporary permission was required

At rest in Phases 0–2 the broker role is assumable by nobody and holds zero
permissions. Attaching the quash SCP in that state produces no observable
change — denied before, denied after — which demonstrates nothing about the SCP.

Section 4.3.3 requires quash to be *exercised*, not merely to exist. Exercising
it requires something for it to remove.

### The bracketed deviation

Gated behind `enable_quash_test_permission` (bool, default `false`), added to
`terraform/bootstrap/`. A variable rather than a temporary file edit: a tfvars
flip cannot be accidentally committed, and the switch documents its own
constraints.

With the flag on and `broker_trusted_principal_arns` populated with the
operator's Identity Center admin role, three things changed:

| | At rest | During the exercise |
|---|---|---|
| Trust policy | `Deny` on `Principal: *` | `Allow` on the operator's SSO role |
| Permissions boundary | No `Allow` statement | `s3:ListAllMyBuckets` on `*` |
| Identity policy | Not created (`count = 0`) | Created, granting the same |

`s3:ListAllMyBuckets` returns bucket names only. It reads no object data and
mutates nothing.

**SSO role ARN gotcha:** the trust policy requires the *role* ARN, which for
Identity Center roles includes a path segment that `get-caller-identity` does
not display. The session ARN shows
`assumed-role/AWSReservedSSO_AdministratorAccess_<hash>/<user>`, but the role
ARN is
`arn:aws:iam::<sandbox-account-id>:role/aws-reserved/sso.amazonaws.com/ap-southeast-1/AWSReservedSSO_AdministratorAccess_<hash>`.
Retrieved via `aws iam get-role`. Using the ARN without the path is accepted by
IAM as a valid policy but never matches, producing an `AccessDenied` with no
indication of the cause.

### Sequence and results

**1. Assumed the broker role.** Session identity confirmed as
`arn:aws:sts::<sandbox-account-id>:assumed-role/writ-broker/a04-quash-test`.

**2. `aws s3api list-buckets` — succeeded.** Returned the two STS lab buckets.
This is the before-state.

**3. Attached the quash SCP** from a separate terminal using the management
profile. The broker's exported session credentials cannot make this call: sec.
4.2.3 denies the broker `organizations:*`, and the policy lives in an account
the broker has no access to.

```bash
aws organizations attach-policy \
  --policy-id p-mphj9kb6 \
  --target-id ou-zg8s-xkkyz4wh \
  --profile writ-management
```

**4. `aws s3api list-buckets` — denied.** Same session, same credentials, no
change to any policy in the sandbox account:

```
An error occurred (AccessDenied) when calling the ListBuckets operation:
User: arn:aws:sts::<sandbox-account-id>:assumed-role/writ-broker/a04-quash-test
is not authorized to perform: s3:ListAllMyBuckets with an explicit deny in a
service control policy:
arn:aws:organizations::<management-account-id>:policy/o-th9tld0ono/service_control_policy/p-mphj9kb6
```

This is the evidence for sec. 4.3.2. The denial names the service control policy
by ARN and attributes it to the management account. Nothing in the sandbox
changed between steps 2 and 4; the broker was cut off from outside its own
account by a policy it cannot read, modify, or detach.

**5. Detached the SCP.**

**6. `aws s3api list-buckets` — succeeded again.** Confirms quash is reversible
and that the denial in step 4 came from the SCP rather than from an unrelated
change.

### Revert

- `enable_quash_test_permission` set back to `false`
- `broker_trusted_principal_arns` set back to `[]`
- `terraform apply` — 0 to add, 2 to change, 1 to destroy, the exact mirror of
  the forward plan
- `terraform plan` — **no changes**, confirming configuration and infrastructure
  agree

Independently verified against AWS rather than against Terraform state:

```bash
aws organizations list-policies-for-target \
  --target-id ou-zg8s-xkkyz4wh \
  --filter SERVICE_CONTROL_POLICY \
  --profile writ-management
```

Returned `FullAWSAccess` only. The quash policy is detached.

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::<sandbox-account-id>:role/writ-broker \
  --role-session-name post-revert-check \
  --profile writ-sandbox
```

Returned `AccessDenied` — the trust policy is back to denying all principals.

### Prediction that proved wrong

The quash SCP matches on `aws:PrincipalArn` using `ArnEquals` against the
broker's role ARN. It was anticipated that `aws:PrincipalArn` might resolve to
the assumed-role *session* ARN (`arn:aws:sts::...:assumed-role/writ-broker/<session>`)
rather than the role ARN, in which case `ArnEquals` would never match and the
SCP would silently fail to deny. The planned fix was switching the condition to
`ArnLike` with a wildcard.

It did not occur. `aws:PrincipalArn` resolved to the role ARN and the condition
matched on the first attempt. **No change to the SCP was needed.** Recorded
because the alternative is plausible enough to be worth ruling out explicitly
rather than rediscovering.

### Denial reasons observed across the project

Four distinct denial messages have now been seen, each naming a different
enforcement layer. Useful as a diagnostic vocabulary:

| Message | Layer |
|---|---|
| `because no session policy allows...` | Session policy narrower than the role |
| `because no identity-based policy allows...` | Role narrower than the session policy |
| `implicitDeny` (simulation) | Nothing allows it; no deny statement matched |
| `with an explicit deny in a service control policy` | Organizations SCP |

## A0.5 — budget alarms

- **Date:** 2026-09-04
- **Status:** partially satisfied

### Budgets confirmed to exist

| Budget | Scope | Threshold | Alert type |
|---|---|---|---|
| My Monthly Cost Budget | Org-wide | $10 | Actual |
| My Zero-Spend Budget | Org-wide | $1 | Actual |
| Sandbox Zero Budget | Sandbox account only | $1 | Actual |

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

### Resolved defect — sandbox budget filter

"Sandbox Zero Budget" was created in the management account but its
linked-account filter was set to `<management-account-id>` rather than
`<sandbox-account-id>`. The account picker defaults to the signed-in account,
and the default was accepted.

The budget name said "Sandbox"; the filter did not. Confirmed by a forecast of
$0.876 on 2026-09-04, matching the org-wide budget rather than the sandbox's $0
history.

**Corrected 2026-09-09.** The linked-account filter now lists
`<sandbox-account-id>` only; `<management-account-id>` removed. The picker had
not previously offered the sandbox account because it had generated no billing
records; that lag resolved.

A0.5 remains **Partial**. The alarm is now correctly configured but has not
fired, because sandbox spend is $0. Firing will be confirmed during Phase 1
fixture capture, per the subsection above.

### Verification caveat — `CostFilters` is not evidence

`CostFilters` is absent from both `describe-budgets` and `describe-budget`
output even when a linked-account filter is correctly applied. **Do not treat an
empty `CostFilters` as evidence that a budget is unscoped.**

Verify scope in the console, or by the presence or absence of `ForecastedSpend`:
a correctly-scoped budget on an account with no spend history omits the forecast
entirely. Before the fix the forecast read $0.692, matching the management
account's baseline; after it, the field is absent.
