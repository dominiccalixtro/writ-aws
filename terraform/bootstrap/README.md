# terraform/bootstrap

Defines the sandbox-account broker identity: docs/IMPLEMENTATION_PLAN.md sec. 4
(Phase 0).

Implemented and applied. A0.1-A0.4 are satisfied and A0.5 is partial; each
result is recorded in `docs/RUNBOOK.md`. This module is the *only* place the
broker role, its permissions boundary, and its explicit deny statements
(sec. 4.2.3) are defined — console-created identities are prohibited
(sec. 4.2.1). No test runs it: `terraform plan` reads the Organization from the
management account, so it needs a live AWS Organization (sec. 4.1).

## Providers

`providers.tf` requires Terraform >= 1.7 and `hashicorp/aws ~> 6.0`, locked at
6.62.0 in the committed `.terraform.lock.hcl`. (`versions.tf` is empty.) It
declares two `aws` providers:

- **Default: the sandbox account** (`sandbox_profile`). Default on purpose: a
  resource that omits `provider` lands in the sandbox, not the management
  account. Everything in `broker.tf` uses it, so the broker role exists only in
  the sandbox (sec. 4.1.3).
- **`aws.management`: the management account** (`management_profile`). Used only
  by `organizations.tf`, for the Organization data source, the sandbox OU, and
  the quash SCP. SCPs are created there and do not restrict that account
  (sec. 4.1.3, 4.3).

There is no backend block: state is local and gitignored, as is `terraform.tfvars`.

## What it defines

| File | Resource | Notes |
|---|---|---|
| `organizations.tf` | OU `writ-sandbox`, under the Organization root | Management account. The attach point for the quash SCP (sec. 4.3.1). |
| `organizations.tf` | SCP `writ-quash-broker` | Management account. Created **detached**. Denies `*` on `*` where `aws:PrincipalArn` `ArnEquals` the broker role's ARN, so quashing does not lock the operator out. Attaching it to the OU is the quash (sec. 4.3.2). |
| `broker.tf` | Managed policy `<broker_role_name>-boundary` | The permissions boundary (sec. 4.2.2); carries the sec. 4.2.3 denies. |
| `broker.tf` | Role `<broker_role_name>` | Sandbox only. Boundary attached, `max_session_duration = 3600`. |
| `broker.tf` | Inline role policy `<broker_role_name>-identity` | Conditional: created only if `capability_role_arns` is non-empty or `enable_quash_test_permission` is true. |
| `outputs.tf` | `sandbox_ou_id`, `quash_policy_id`, `broker_role_arn`, `broker_boundary_policy_arn` | Inputs to move-account, quash, and simulation. |

No budget resource is defined here. The sec. 4.4.1 budgets exist outside this
module; see A0.5 in `docs/RUNBOOK.md`. `management_account_id` is validated as
12 digits but no resource references it.

### The denies

Explicit `Deny` statements in the boundary (sec. 4.2.4), not the absence of
`Allow`:

- `DenyEscalation` — six `iam:` actions, `organizations:*`, `account:*`.
- `DenyEvidenceIntegrityCloudTrail` — `StopLogging`, `DeleteTrail`,
  `UpdateTrail`, `PutEventSelectors`.
- `DenyEvidenceIntegrityTrailBucket` — nine `s3:` bucket and object actions on
  `trail_log_bucket_arn` and `<arn>/*`. That variable is a placeholder until a
  trail bucket exists, so the statement matches nothing yet.
- `DenyAssumeRoleOutsideCapabilityRoles` — `sts:AssumeRole` on anything not in
  `capability_role_arns` (`NotResource`). Emitted only when that list is
  non-empty: a `NotResource` over an empty list denies everything and would
  permanently block Phase 3.

## State at rest (Phases 0-2)

With `capability_role_arns = []`, `broker_trusted_principal_arns = []` and
`enable_quash_test_permission = false` — the values in
`terraform.tfvars.example` — effective permissions are zero, three independent
ways:

- **Trust policy:** a single `Deny` on `sts:AssumeRole` for `Principal: *`
  (`DenyAllUntilPhase3`). No principal can assume the role. Populating
  `broker_trusted_principal_arns` replaces it with an `Allow` on those
  principals; the two are mutually exclusive, because an explicit Deny beats any
  Allow.
- **Permissions boundary:** no `Allow` statement, only the denies above. A
  boundary is an intersection, so the ceiling is zero.
- **Identity policy:** not created (`count = 0`).

Any one of the three is sufficient alone. In this state the module creates four
resources: the role, the boundary policy, the OU, and the quash SCP.

## `enable_quash_test_permission`

Default `false`. **It MUST be false outside the A0.4 exercise.** When true it
adds `s3:ListAllMyBuckets` on `*` to the boundary and to the identity policy
(which is then created), so quash has a permission to remove. The role is
assumable only if `broker_trusted_principal_arns` is also populated. At rest,
attaching the quash SCP changes nothing observable, and sec. 4.3.3 requires
quash to be exercised, not merely to exist. The exercise and its revert are
recorded under A0.4 in `docs/RUNBOOK.md`, including the Identity Center role-ARN
path gotcha for `broker_trusted_principal_arns`.

## Planning from a fresh clone

```bash
cd terraform/bootstrap
cp terraform.tfvars.example terraform.tfvars   # gitignored; then set real values
terraform init                                 # resolves the provider from the committed lock file
terraform plan
```

Set `sandbox_account_id`, `management_account_id`, `sandbox_profile` and
`management_profile` to real values. The example carries `123456789012` for
both accounts and placeholder profile names and trail bucket ARN; none of it is
real. A fresh clone has no state, so plan reports every resource as
to-be-created: with the at-rest values, the four resources above. A0.2 recorded
`4 to add, 0 to change, 0 to destroy` and reads the criterion as "plan runs
without error given a valid tfvars file", not "no changes" (`docs/RUNBOOK.md`).

**Validating an alternative variable file requires a directory with no state.**
Do not pass `-var-file` in a directory that holds the live state. Terraform
compares that state against the placeholder accounts and shows the live quash
SCP as an ordinary in-place update pointing at the wrong account, with no
warning (`docs/RUNBOOK.md`, A0.2).

## Moving the sandbox account into the OU

Manual, one-time, and not managed in Terraform: `aws_organizations_account`
would put the account in state, and `terraform destroy` would then try to close
it, a 90-day irreversible operation that would violate sec. 4.4.4. Until the
account is in the OU, the quash SCP cannot affect it. Run it with the management
profile:

```bash
aws organizations move-account \
  --account-id <sandbox-account-id> \
  --source-parent-id <root-id> \
  --destination-parent-id <sandbox_ou_id output> \
  --profile <management-profile>
```

The root ID comes from `aws organizations list-roots`. The `SERVICE_CONTROL_POLICY`
policy type must also be enabled on the root before the SCP can be attached; the
pre-flight is under *Quash* in `docs/RUNBOOK.md`.

## Recorded results

All in `docs/RUNBOOK.md`:

- **A0.1** — broker role exists only in the sandbox; the four resources; the
  at-rest state above.
- **A0.2** — fresh-clone plan; the interpretation applied; two defects it
  surfaced; the warning about alternative variable files.
- **A0.3** — the declared sec. 4.2.3 denies verified as `explicitDeny` by
  `simulate-principal-policy`, with a negative control. Two limitations:
  wildcard denies (`organizations:*`, `account:*`) cannot be verified by
  simulation, and the boundary-escape deny does not exist while
  `capability_role_arns` is empty.
- **A0.4** — quash exercised, using `enable_quash_test_permission`, then
  reverted.
- **A0.5** — budgets exist (partial): the alarm has not yet been confirmed to
  fire; that is planned for Phase 1 capture.

## Left for Phase 3

Phase 3 is out of contract (sec. 12). These are recorded so they are not
mistaken for oversights:

- Populating `capability_role_arns` and `broker_trusted_principal_arns`
  (`broker.tf`: the trust `Deny` must be removed, not supplemented).
- Verifying the boundary-escape deny by simulation when `capability_role_arns`
  is first populated (A0.3, limitation 2).
- Replacing the `trail_log_bucket_arn` placeholder once the trail and bucket
  exist.
