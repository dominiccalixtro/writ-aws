# ADR-001: STS Scoping Model for Writ Execution

- **Status:** Proposed
- **Date:** 2026-09-02
- **Phase:** 3 (first phase with live AWS access)
- **Supersedes:** none

> **This ADR records findings and proposes decisions. It does not authorise
> implementation.** Phase 3 remains out of contract under
> `IMPLEMENTATION_PLAN.md` §12 until that document is extended. The evidence in
> this ADR is Phase 0 boundary verification and is additionally recorded in
> `docs/RUNBOOK.md`.

---

## Context

Phases 0–2 of `writ-aws` are CLI-only with zero network calls. Phase 3 is the first
phase in which an admitted petition results in a real mutation against AWS. This
requires answering: what credential does an executor hold, where does it come from,
and what bounds it.

The threat model for this phase is not primarily an external attacker. It is:

1. A compromised or malfunctioning agent proposing a harmful petition.
2. **A bug in the broker's own admission or scoping code.**

(2) is the harder problem. Any design in which broker-side Python is the sole
enforcement point fails open when that Python is wrong. The scoping model must be
chosen so that broker bugs are bounded by something the broker cannot influence.

---

## Decision

### D1 — Writs are STS sessions produced by `AssumeRole` with an inline session policy

A writ is not a credential the broker mints. It is a short-lived STS session obtained
by assuming a capability role, with a per-writ inline session policy that narrows
scope to the specific resource named in the petition.

Effective permissions are the **intersection** of the role's identity policy and the
session policy. This is computed and enforced by AWS, not by broker code.

### D2 — One IAM role per capability, not one role downscoped per writ

Each allowlisted remediation class maps deterministically to exactly one capability
role:

```
writ-cap-s3-block-public-access
writ-cap-sg-revoke-ingress
writ-cap-iam-deactivate-access-key
```

The broker MUST NOT hold or use a general-purpose execution role that is narrowed
only by session policy.

Rationale is quantitative, not stylistic: a session-policy construction bug costs
exactly as much as the capability role is broad. See Evidence below — the same
defective session policy yielded zero additional access on a narrow role and full
`s3:*` on a broad one.

IAM roles are free. There is no cost argument against proliferating narrow roles.

D2 is the reason for the amendment to `IMPLEMENTATION_PLAN.md` §3.6 (item 6 of
section 3), which now scopes a writ against the permissions of the capability
role it assumes rather than the broker role's own, and for the addition of
invariant **I9** — the broker role holds no direct write capability, its only
permitted action being `sts:AssumeRole` on capability roles enumerated in the
bootstrap module.

### D3 — Broker code is the least-trusted enforcement layer

Defence layers, ordered by trust:

| Layer | Enforced by | Broker can bypass | Cost |
|---|---|---|---|
| SCP on member account | AWS Organizations | No | Free |
| Permissions boundary on capability roles | IAM | No, if boundary modification is SCP-denied | Free |
| Capability role identity policy | IAM | Only if it holds `iam:PutRolePolicy` | Free |
| Per-writ session policy | STS intersection | No | Free |
| Broker admission checks (Python) | Broker code | **Yes, via bug** | — |

Corollary: the broker MUST NOT run in the AWS Organizations management account.
SCPs do not apply there, silently removing the outermost layer.

### D4 — Every narrowing decision MUST be expressible in the session policy

If the admission policy computes a constraint that cannot be encoded in IAM, that
constraint is advisory commentary, not enforcement.

Where a constraint cannot be expressed in IAM, one of the following applies:

- It moves to a pre-flight read performed inside the scoped session, or
- The capability is not allowlisted until it can be enforced.

---

## Evidence

Two IAM roles and two S3 buckets were created in the sandbox account. All tests were
run from the CLI. No results below are inferred; each is an observed CLI response.

**Roles**

| Role | Identity policy |
|---|---|
| `writ-lab-narrow` | `s3:PutBucketPublicAccessBlock`, `s3:GetBucketPublicAccessBlock`, `s3:ListAllMyBuckets` on `*` |
| `writ-lab-broad` | `s3:*` on `*` |

**Session policies**

| File | Contents |
|---|---|
| `session-alpha.json` | Get/Put public access block, `Resource` = alpha bucket ARN only |
| `session-escalate.json` | `ec2:*`, `iam:*`, `s3:*` on `*` — deliberately over-permissive |

### Test 2 — Resource scoping and action subtraction (narrow role + `session-alpha.json`)

| Call | Result |
|---|---|
| `get-public-access-block` on **alpha** | Succeeded |
| `get-public-access-block` on **beta** | `AccessDenied` — *no session policy allows* |
| `list-buckets` | `AccessDenied` — *no session policy allows* |

Two distinct properties confirmed:

- **Resource narrowing.** Same role, same credentials, same action; alpha permitted
  and beta denied purely by session-policy resource scope.
- **Action subtraction.** The role grants `s3:ListAllMyBuckets`. The session policy
  omitted it. The permission was removed. Narrowing operates on actions as well as
  resources.

### Test 3 — Escalation refused (narrow role + `session-escalate.json`)

The `AssumeRole` call **succeeded**. AWS does not reject an over-permissive session
policy; it silently declines to honour the excess. This is important: there is no
error signal at issue time to detect this class of bug.

| Call | Result |
|---|---|
| `ec2:DescribeInstances` | `UnauthorizedOperation` — *no identity-based policy allows* |
| `iam:ListUsers` | `AccessDenied` — *no identity-based policy allows* |
| `s3:DeleteBucket` on beta | `AccessDenied` — *no identity-based policy allows* |

A session policy explicitly granting `ec2:*`, `iam:*` and `s3:*` produced no
additional access whatsoever. The role is the ceiling.

### Test 4 — Same defect, broad role (`writ-lab-broad` + `session-escalate.json`)

| Call | Result |
|---|---|
| `ec2:DescribeInstances` | `AccessDenied` — role never had EC2 |
| `list-buckets` | **Succeeded** — returned both buckets |

`s3:DeleteBucket` on either bucket would also have succeeded.

### Test 3 vs Test 4 — the decisive comparison

| | narrow role | broad role |
|---|---|---|
| Session policy | `ec2:*`, `iam:*`, `s3:*` | identical |
| EC2 | denied | denied |
| `list-buckets` | denied | **succeeded** |
| `delete-bucket` | denied | **would succeed** |

Identical broker defect. Blast radius differs entirely by capability-role breadth.
This is the evidence for D2.

---

## Operational finding: denial reasons identify the failing layer

AWS denial messages name which side of the intersection rejected the call:

| Message fragment | Meaning | Likely bug |
|---|---|---|
| `because no session policy allows...` | Role permitted it; session policy did not | Writ scoped too tightly, or petition resource mis-parsed |
| `because no identity-based policy allows...` | Session policy permitted it; role did not | Capability role missing a required action, or wrong role selected for the petition |

These are different failures with different fixes. Decision records SHOULD capture
the full denial string from failed executions rather than a normalised
`AccessDenied`, since the distinction is lost by normalising.

---

## Constraints discovered

| Constraint | Value | Consequence for design |
|---|---|---|
| Session policy size | 2048 characters plaintext | Enumerating many resource ARNs exhausts the budget. Prefer tag-based conditions for multi-resource writs. |
| Managed policy ARNs as session policy | 10 maximum | Use for capability shape; use inline for per-writ resource narrowing. |
| `DurationSeconds` minimum | 900s (15 minutes) | **"Short-lived" bottoms out at 15 minutes.** The STS minimum coincides with the contract ceiling of 900s, so **900 is the sole legal term value** — see `IMPLEMENTATION_PLAN.md` §7.7, under which no writ is constructible with any other term. A 5-minute writ is not obtainable; a shorter effective lifetime would have to be enforced by the executor, not by STS. |
| Role chaining maximum | 3600s (1 hour) | Applies if the broker itself runs under an assumed role, which it will under IAM Identity Center. |
| `RoleSessionName` charset | `[\w+=,.@-]`, 2–64 chars | No colons or slashes. ULIDs and truncated digests are usable; ARNs are not. |

---

## Consequences

### Accepted

- Writ issuance requires an `AssumeRole` call per admitted petition. Adds latency and
  a network dependency to the execution path (not the decision path).
- Capability roles must be provisioned in Terraform ahead of any petition referencing
  them. New capabilities require an infrastructure change, not just an allowlist edit.
  This is intended friction.
- `MaxSessionDuration` MUST be set on each capability role (900–3600s) so the ceiling
  is IAM-enforced regardless of what the broker requests.

### Required follow-on controls

- Credentials held in memory only. Never written to disk, never exported to
  environment variables in the broker process.
- Failure of `AssumeRole`, session policy size overflow, or any exception during
  policy construction MUST deny. There is no fallback to a broader role and no
  fallback to ambient credentials.
- `RoleSessionName` MUST embed the writ ID, giving CloudTrail attribution from every
  mutation back to a decision record and its plan digest.
- Session tags SHOULD carry `writ_id`, `petition_digest`, `policy_version`.
- `aws:RequestedRegion` MUST be constrained in both the session policy and the SCP.
- CloudTrail to S3 with object lock; `cloudtrail:StopLogging` and
  `cloudtrail:DeleteTrail` denied by SCP so the broker cannot erase its own trail.

---

## What this ADR does NOT cover

**Intersection bounds damage. It does not establish correctness.**

A writ scoped to exactly one action on exactly one resource can still be *wrong*.
Blocking public access on a bucket intentionally serving a public static site is
fully in scope and fully authorised — AWS will permit it without complaint.

Semantic correctness is the job of the admission policy (allowlist, resource scope,
blast radius, expected-state assertion), which is entirely broker-side code. That is
where the interesting failure modes live, and it is not addressed here.

Also out of scope, deferred to subsequent ADRs:

- **TOCTOU.** Time gap between finding, petition, admission, and execution. The
  resource may have changed. Mitigation direction: writs carry an expected-state
  assertion verified inside the scoped session before mutating; use `DryRun` where
  the API supports it.
- **Once-only execution.** Broker-side ledger keyed on writ ID, written before the
  call. Unknown outcomes reconcile by re-reading state, never by blind retry.
  `Revoke*` calls are naturally idempotent; `Create*` calls are not.

---

## Contract alignment

This ADR prompted two amendments to `docs/IMPLEMENTATION_PLAN.md`:

1. **§3.6 + I9** — item 6 of section 3 rewritten so a writ's scope narrows against the
   capability role it assumes, not against the broker role's own permissions; invariant
   **I9** added to section 8. Reason: D2. I9 has no test — it is unverifiable until
   `terraform/bootstrap/` exists.
2. **§7.7 term note** — the STS `DurationSeconds` minimum of 900s recorded against the
   contract ceiling of 900s, making 900 the sole legal term — no writ is
   constructible with any other. I7 is unchanged and remains expressed as a ceiling.

### Phase 0 is incomplete

Phase 0–2 *code* scaffolding is done. Phase 0 on the AWS side is partially done. The
lab exercise recorded above is preparatory verification and satisfies **no** A0
criterion — that remains true. What has changed since this ADR was first written is
that `terraform/bootstrap/` has been written and applied, which satisfies A0.1 and made
A0.3 verifiable.

Status only; the evidence is in `docs/RUNBOOK.md`.

| Criterion | Status |
|---|---|
| **A0.1** | **Satisfied** — the broker role exists in the sandbox account and nowhere else. |
| **A0.2** | Outstanding — fresh-clone `terraform plan` not yet performed. |
| **A0.3** | **Satisfied**, with two recorded limitations: a wildcard deny cannot be exhaustively verified by `simulate-principal-policy`, which requires concrete action names; and the boundary-escape deny emits no statement while `capability_role_arns` is empty, so there is nothing to simulate. |
| **A0.4** | Outstanding — quash not yet exercised. |
| **A0.5** | Partial — alarms exist; firing unconfirmed; the sandbox budget's linked-account filter is incorrect. |

I9 remains unverified for the same reason as A0.3's second limitation, and is a Phase 3
dependency: it must be checked when `capability_role_arns` is first populated.

## Open questions

| Question | Impact | Status |
|---|---|---|
| **SigV4 hand-rolled vs boto3** | boto3 falls back to the default credential chain (env, `~/.aws/credentials`, IMDS). A bug in the credential-passing path would silently succeed using the broker's own credentials rather than the scoped writ — the exact failure this design exists to prevent. A hand-rolled signer taking explicit credentials as arguments makes that structurally impossible, at the cost of owning security-critical crypto plumbing. Also determines whether stdlib-only survives into Phase 3. | Undecided |
| **Broker authentication origin** | IAM Identity Center (browser login, temporary credentials, no stored secret) vs IAM user with long-lived access keys on disk. The latter undercuts the project's premise. | Undecided |
| **First capability** | Build the full narrowing stack end-to-end against one capability before adding a second. Candidates: `s3:PutPublicAccessBlock`, `ec2:RevokeSecurityGroupIngress` — both small blast radius, both idempotent. | Undecided |
| **Permissions boundary scope** | §4.2.2 requires a permissions boundary on the broker role. Under the capability-role design, it is unresolved whether the boundary must also apply to capability roles — otherwise the boundary constrains the broker while the roles it assumes sit outside it. | Undecided |

---

## Incidental observations

- Newly created S3 buckets returned `BlockPublicAcls`, `IgnorePublicAcls`,
  `BlockPublicPolicy` and `RestrictPublicBuckets` all `true` by default. S3 has
  enabled public access block on new buckets by default since April 2023. This
  slightly weakens `s3:PutPublicAccessBlock` as a first capability, since the
  remediation is less frequently needed on modern buckets than on legacy ones.
- IAM Identity Center authenticates via `AssumeRole` and issues temporary credentials
  with a session name — structurally the same mechanism as a writ, differing only in
  scope and duration.

---

## Lab teardown

Sandbox resources created for this ADR. All four were created from the CLI and are
**not** managed by Terraform, so `terraform destroy` will not remove them. They are
**scheduled for deletion, pending operator action** — leaving them creates untracked
drift in an account A1.4 expects to be clean, and `writ-lab-broad` grants `s3:*`.

```
IAM role   writ-lab-narrow  (inline policy: narrow)
IAM role   writ-lab-broad   (inline policy: broad)
S3 bucket  writ-lab-alpha-<account-id>
S3 bucket  writ-lab-beta-<account-id>
```

The exact teardown commands are recorded in `docs/RUNBOOK.md`. They have not been
run; the operator executes them.

Scratch policy JSON lives in `.lab/`, which is gitignored. `broad-policy.json`
grants `s3:*` and must never be committed — it contradicts the implementation
contract and would mislead any later reader of the repository.
