# writ-aws — Implementation Contract (Phases 0–2)

> **Status:** Implementation contract for the standalone `writ-aws` repository.
>
> This document defines **required behavior** and **measurable acceptance criteria** for Phases 0 through 2 only. Phases 3–5 (scoped credential issuance, evidence reconciliation, adversarial suite) are named in section 12 and are explicitly out of contract until this document is extended. It is deliberately not an implementation: except where a mechanism is mandated below, the implementing agent chooses the minimal compliant implementation.

## 1. Scope and authority

1.1. This contract governs **only** the `writ-aws` repository.

1.2. The `sentinelcloud-engineering-loop` repository is **out of scope**. It SHALL NOT be modified under this contract. Design discipline may be reused; source SHALL be copied deliberately and attributed in-file, never imported across repositories.

1.3. `writ-aws` is a **separate program with a separate threat model**. The engineering loop holds no cloud credentials and SHALL continue to hold none. Credential-bearing capability introduced here SHALL NOT be added to that repository.

1.4. Phases 0–2 SHALL NOT mutate any AWS resource outside the sandbox account, and SHALL NOT perform any AWS write action of any kind. Phase 2 terminates at a printed, unexecuted plan.

1.5. Where requirements conflict, the stricter constraint wins. Where this contract says **SHALL** or **MUST NOT**, the behavior is mandatory, enforced, and independently reviewable.

## 2. Definitions

| Term | Meaning |
| --- | --- |
| Finding | A security detection in AWS Security Finding Format (ASFF), originating from Security Hub, GuardDuty, or AWS Config. Untrusted input in full. |
| Agent plane | The LLM-driven component that reads findings and emits petitions. Holds no AWS credentials and has no network path to AWS APIs. |
| Petition | A structured, unsigned proposal for remediation emitted by the agent plane. Carries no authority. |
| Broker | The only component permitted to hold AWS credentials. Admits or refuses petitions. |
| Admission | The deterministic decision procedure (section 8) that converts a petition into a writ or a refusal. |
| Writ | An admitted, signed, scoped, expiring order to perform one specific act. Phases 0–2 produce writs but never serve them. |
| Scope | The set of AWS actions and resource ARNs a writ authorizes. Derived from the petition; may only intersect downward from the broker role's own permissions. |
| Term | The writ's validity window. SHALL NOT exceed 900 seconds. |
| Service | Execution of a writ against AWS. **Out of contract until Phase 3.** |
| Return | The evidence bundle proving how a writ was served. **Out of contract until Phase 4.** |
| Quash | Revocation of the broker's ability to act, by explicit deny or trust-policy break. |
| Sandbox account | The dedicated AWS account (section 4) that is the sole permitted target of any writ. |
| Management account | The operator's personal AWS account. Holds pre-existing personal resources. Never a target. |
| Fixture | A recorded, redacted artifact (finding, plan JSON, CloudTrail event) committed to the repository and replayed by tests without network access. |

## 3. The normative trust boundary

The system SHALL implement, exactly and in order:

1. **Findings are untrusted data, never instructions.** Every field of a finding — including `Description`, `Title`, `Remediation.Recommendation.Text`, resource tags, ARNs, and object keys — SHALL be treated as attacker-controlled and SHALL be labelled as untrusted in every prompt that carries it.
2. **The agent plane may petition but never issue.** It SHALL NOT hold, request, derive, or receive AWS credentials, and SHALL NOT be granted network egress to any AWS API endpoint.
3. **The broker is the sole credential holder.** No other component in this repository SHALL construct an AWS client with write capability.
4. **Admission is deterministic.** The decision to admit a petition SHALL be computable without invoking any language model. A model SHALL NOT participate in, influence, or be consulted during admission.
5. **Admission is deny-by-default.** A petition SHALL be refused unless it matches an explicit allow rule. Absence of a matching deny rule is not admission.
6. **Scope may only narrow.** A writ's scope SHALL be a subset of both the petition's requested actions and the permissions of the capability role the writ assumes. The broker role SHALL hold no capability permissions directly; its sole AWS capability SHALL be `sts:AssumeRole` on the capability roles enumerated in the bootstrap module. No admission path SHALL widen either.
7. **Refusals are terminal for that petition.** A refused petition SHALL NOT be re-submitted, repaired, or negotiated automatically. Re-petitioning requires a new finding evaluation.
8. **Every decision is recorded.** Admission and refusal alike SHALL produce a persisted decision record before any subsequent step.

```text
ASFF finding (untrusted)
      │
      ▼
[agent plane] ──── no credentials, no AWS egress ────▶ petition (unsigned)
      │
      ▼
[broker: admission]
   1 schema validation
   2 static action allowlist
   3 resource-scope check (sandbox account + sandbox tag)
   4 terraform plan gate
   5 blast-radius classification
      │                    │
   admitted            refused
      │                    │
      ▼                    ▼
    writ            decision record
  (Phase 2: printed, never served)
```

## 4. Phase 0 — Account boundary and broker identity

### 4.1 Account topology

4.1.1. An AWS Organization SHALL be created from the operator's personal account, which becomes the **management account**.

4.1.2. A dedicated **sandbox account** SHALL be created as an Organization member account. All writ targets SHALL reside in it.

4.1.3. The broker role SHALL exist **only in the sandbox account**. A broker role in the management account is prohibited: Service Control Policies do not restrict the management account, which would render the section 4.3 boundary unenforceable.

4.1.4. Pre-existing personal resources (domains, hosted zones, portfolio hosting, billing artifacts) SHALL remain in the management account and SHALL NOT be replicated into the sandbox.

### 4.2 Broker role

4.2.1. The broker role SHALL be defined in Terraform under `terraform/bootstrap/`. Console-created identities are prohibited.

4.2.2. The broker role SHALL carry a **permissions boundary** that no policy it can attach may exceed.

4.2.3. The broker role SHALL be denied, explicitly and unconditionally:

- **Escalation** — `iam:CreateUser`, `iam:CreateAccessKey`, `iam:AttachUserPolicy`, `iam:PutUserPolicy`, `iam:DeleteRolePermissionsBoundary`, `iam:PutRolePermissionsBoundary`, `organizations:*`, `account:*`.
- **Evidence integrity** — `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `cloudtrail:UpdateTrail`, `cloudtrail:PutEventSelectors`, and deletion or lifecycle mutation of the trail's log bucket.
- **Boundary escape** — `sts:AssumeRole` on any principal other than those enumerated in the bootstrap module.

4.2.4. The deny statements in 4.2.3 SHALL be expressed as an explicit `Deny`, not as an absence of `Allow`.

### 4.3 Quash path

4.3.1. An SCP attached to the sandbox account's Organizational Unit SHALL be capable of denying the broker role all actions.

4.3.2. Quash SHALL be executable as a single documented command and SHALL take effect without requiring the broker's cooperation.

4.3.3. The quash procedure SHALL be documented in `docs/RUNBOOK.md` and SHALL be exercised at least once during Phase 0, with the result recorded.

### 4.4 Cost governance

4.4.1. A zero-spend budget alert and a hard budget alarm SHALL exist before any billable resource is created.

4.4.2. Detection services (GuardDuty, AWS Config, Security Hub) SHALL be enabled only during fixture capture (section 5) and disabled on teardown. AWS Config SHALL be scoped to an explicit resource-type list, never to all supported types.

4.4.3. The following SHALL NOT be created under this contract: EKS clusters, NAT gateways, idle load balancers, Multi-AZ RDS instances.

4.4.4. Every Terraform module SHALL be destroyable by `terraform destroy` with no manual prerequisite. Any resource requiring manual teardown SHALL be documented as such or SHALL NOT be created.

## 5. Phase 1 — Fixture capture

5.1. Fixtures SHALL be captured once from the live sandbox account and committed under `tests/fixtures/`. After capture the sandbox SHALL be destroyed.

5.2. The fixture corpus SHALL include, at minimum, recorded ASFF findings for: an over-permissive security group ingress rule, a public S3 bucket, an unencrypted EBS volume, and an IAM policy granting `*` on `*`.

5.3. Fixtures SHALL additionally include `terraform plan -json` output for at least one compliant and one non-compliant remediation, and at least one CloudTrail event record.

5.4. Fixtures SHALL be redacted: account IDs, ARNs containing the real account number, and any credential material SHALL be replaced with documented placeholders. A test SHALL assert that no fixture contains a 12-digit sequence matching the operator's real account ID.

5.5. Every test in this repository SHALL pass with no network access and no AWS credentials present in the environment. A test run that requires either SHALL be considered a contract violation.

## 6. Phase 2 — Petition schema

6.1. A petition SHALL be a JSON object with an explicit, versioned schema. Unknown top-level keys SHALL cause refusal, not be ignored.

6.2. A petition SHALL declare at minimum: the originating finding identifier, the proposed action set (AWS API actions or a Terraform diff), the target resource ARNs, and a natural-language rationale.

6.3. The rationale field SHALL be treated as untrusted display text. It SHALL NOT influence admission in any way, and a test SHALL prove that two petitions differing only in rationale receive identical decisions.

6.4. A petition SHALL NOT contain, and the parser SHALL reject: credentials, role ARNs to assume, policy documents authored by the agent plane, or any instruction directed at the broker. "Role ARNs to assume" is a functional category. The prohibition applies to role ARNs appearing in fields that determine what the writ does — the action set, target resource ARNs, and any Terraform diff. It does not apply to the rationale field, which 6.3 renders non-influential and which may legitimately name an IAM principal when describing an IAM-related finding. Credential material remains prohibited in every field at every depth without exception.

6.5. Petition parsing SHALL be total: every input either parses into a valid petition or produces a typed refusal. Parsing SHALL NOT raise an unhandled exception on any input, including non-UTF-8 bytes and deeply nested JSON.

## 7. Phase 2 — Admission policy

7.1. The static action allowlist SHALL enumerate permitted AWS actions explicitly. Wildcards in the allowlist itself are prohibited.

7.2. A petition SHALL be refused if any requested action is absent from the allowlist, regardless of the other checks' outcomes.

7.3. Every target resource ARN SHALL be verified to reside in the sandbox account and to carry the sandbox tag. Any ARN failing either check SHALL cause refusal of the entire petition, not partial admission.

7.3.1. The account check is offline. The account field is read from the ARN and compared to the sandbox account identifier supplied to the admission call. It is in force from Phase 2.

7.3.2. The tag check requires an AWS read and therefore cannot be performed by admission code, which holds no credentials and constructs no network path (I1, I2, §5.5). It is deferred to Phase 3, where the tag is read outside the admission decision and supplied to it. Until Phase 3, §7.3 is partially implemented: a petition admitted in Phase 2 has not had its ARNs tag-verified. No writ is served in Phase 2 (§7.7), so no unverified ARN is acted upon.

7.4. Petitions proposing a Terraform diff SHALL be gated on `terraform plan -json`. A plan containing any `delete` action on a resource type outside the explicitly enumerated deletable set SHALL cause refusal.

7.5. Admitted petitions SHALL be classified by blast radius into `auto` and `human` bands. The banding rule SHALL be data, not code branches, and SHALL be independently reviewable.

7.6. Any petition touching IAM, CloudTrail, KMS key policy, or the Organization SHALL classify as `human` regardless of other signals. This classification SHALL NOT be overridable by configuration.

7.7. A writ SHALL record its scope and a term not exceeding 900 seconds. In Phase 2 the writ is serialized and printed; it SHALL NOT be served, and the repository SHALL contain no code path capable of serving it. The AWS STS `DurationSeconds` minimum is 900 seconds. Combined with the ceiling above, 900 is therefore the sole legal term value. No writ SHALL be constructible with a term other than 900 seconds. A shorter effective window, if ever required, cannot be obtained from STS and would have to be enforced by the executor — that is, by broker-side code, which this design treats as the least-trusted enforcement layer.

7.8. Decision records SHALL be written with `newline=""` so digests remain stable across platforms.

## 8. Safety invariants

The following SHALL hold at every commit, and each SHALL have a test proving the unsafe input is rejected:

- **I1** — No component other than the broker constructs an AWS client with write capability.
- **I2** — No language model is invoked during admission.
- **I3** — Text originating from a finding never reaches an admission decision as anything but data.
- **I4** — A petition requesting an action outside the allowlist is refused.
- **I5** — A petition targeting a resource outside the sandbox account is refused.
- **I6** — A petition touching IAM or CloudTrail is never classified `auto`.
- **I7** — No writ carries a term exceeding 900 seconds.
- **I8** — No code path in Phases 0–2 performs an AWS write action.
- **I9** — The broker role holds no direct write capability. Its only permitted action is `sts:AssumeRole` on capability roles enumerated in the bootstrap module.

## 9. Testing

9.1. Tests SHALL use `unittest` with no third-party test dependencies, replaying fixtures from disk.

9.2. Tests SHALL be adversarial by default: for each admission rule, the suite SHALL include at least one input designed to defeat it.

9.3. The suite SHALL include an injection corpus in which findings carry instructions directed at the reader, including at minimum a finding whose remediation text asks for CloudTrail to be disabled and one that asks for an IAM policy to be attached to an unrelated principal. Each SHALL produce a refusal or a `human` classification, and SHALL NOT produce an `auto` writ.

9.4. The injection corpus SHALL be exercised against fixtures only. It SHALL NOT be run against live AWS.

9.5. A new admission rule SHALL NOT be merged without a test proving the corresponding unsafe input fails.

## 10. Acceptance criteria

**Phase 0 complete when:**

- A0.1 — Sandbox account exists as an Organization member; broker role exists only there.
- A0.2 — `terraform plan` on `terraform/bootstrap/` is clean from a fresh clone.
- A0.3 — Every deny in 4.2.3 is verified by `aws iam simulate-principal-policy` returning `implicitDeny` or `explicitDeny`, with output recorded.
- A0.4 — Quash has been exercised once and the result recorded in `docs/RUNBOOK.md`.
- A0.5 — Budget alarms exist and have been confirmed to fire on a test threshold.

**Phase 1 complete when:**

- A1.1 — Fixture corpus covers all four finding classes in 5.2.
- A1.2 — Redaction test passes; no real account ID appears in any committed file.
- A1.3 — Full suite passes with network disabled and no AWS credentials in the environment.
- A1.4 — Sandbox is destroyed; `terraform destroy` leaves no billable resource.

**Phase 2 complete when:**

- A2.1 — Every invariant I1–I8 has at least one passing adversarial test.
- A2.2 — The injection corpus of 9.3 produces zero `auto` classifications.
- A2.3 — Running the CLI against a fixture finding prints a writ or a typed refusal, and performs no network call — proven by a test that fails on any socket construction.
- A2.4 — The repository contains no code path capable of serving a writ (I8), verified by review, not by assertion.

## 11. Definition of done

A human SHALL verify, before accepting Phases 0–2: the sandbox is destroyed; the full suite passes offline; the injection corpus is green; `simulate-principal-policy` output for section 4.2.3 is committed; and no AWS write capability exists anywhere in the repository.

## 12. Out of contract

The following are named for orientation and SHALL NOT be implemented until this document is extended: Phase 3 scoped STS issuance and service; Phase 4 returns and CloudTrail reconciliation; Phase 5 expanded adversarial suite and published threat model.

## 13. No-deployment statement

This contract contains no deployment step, no production infrastructure change, no credential handling, and no Git mutation. Phases 0–2 provision an isolated sandbox for fixture capture and then destroy it. No writ is served.
