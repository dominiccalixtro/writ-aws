# terraform/capture

Phase 1 fixture capture: docs/IMPLEMENTATION_PLAN.md sec. 5. Creates the four
sec. 5.2 finding targets and the detection services that evaluate them. It
exists for one capture window and is destroyed straight after (sec. 5.1).

**Drafted 2026-09-25, not yet applied.** Validated offline only
(`terraform validate` and `fmt -check` against the pinned provider, v6.62.0).
It has never been planned against a live account, so expect the first
`plan` to surface something validation cannot.

## What it creates

| Resource | Why | Fenced by |
|---|---|---|
| Security group, SSH from `0.0.0.0/0` | over-permissive ingress finding | attached to nothing |
| S3 bucket, Block Public Access off | public bucket finding | empty; public *read* only, and only with `s3_public_policy` |
| 1 GiB unencrypted gp3 volume + `t4g.nano` host | unencrypted volume finding (the control checks *attached* volumes) | no public IP, no ingress, no egress, no key pair, encrypted root |
| IAM policy `*` on `*` | admin policy finding | unattached; or, with `attach_admin_policy`, attached to a role whose trust policy denies everyone |
| AWS Config recorder, 4 resource types | evaluates the targets (sec. 4.4.2: explicit type list) | destroyed with the module |
| Security Hub + AWS Foundational Security Best Practices | turns evaluations into ASFF findings | destroyed with the module |

GuardDuty is not enabled. None of the four finding classes comes from it.

The provider is pinned to the sandbox with `allowed_account_ids`: a wrong
profile fails before anything is read or created.

## Cost

Expect well under US$1 for a capture window of a day: a `t4g.nano`, a 1 GiB
and an 8 GiB gp3 volume, and Config/Security Hub evaluations over a handful of
resources. Those are estimates, not quotes. Check Cost Explorer after teardown
and record the real figure in docs/RUNBOOK.md.

**A0.5 note.** The runbook plans to confirm the budget alarm fires during this
capture. If the spend stays under the alarm's *alert threshold* it will not
fire. Check the threshold (not the budget amount) before you start, and
remember billing data lags by hours.

## Pre-flight

Every check reads only.

```bash
P="--profile writ-sandbox --region ap-southeast-1"

aws sts get-caller-identity $P                          # Account must be the sandbox
aws configservice describe-configuration-recorders $P   # expect [] (one recorder per region)
aws securityhub describe-hub $P                         # expect InvalidAccessException: not enabled
aws ec2 get-ebs-encryption-by-default $P                # expect false, or the volume precondition fails
aws ec2 describe-vpcs --filters Name=is-default,Values=true --query 'Vpcs[].VpcId' $P  # expect one VPC
```

**Only if `s3_public_policy = true`:** the account-level S3 Block Public Access
must allow public policies, or AWS rejects the bucket policy with
`AccessDenied`. That rejection is the intended failure: the module never
changes account-level settings. Record the current state first, then relax
only the two policy settings:

```bash
aws s3control get-public-access-block --account-id <sandbox-id> --profile writ-sandbox
# NoSuchPublicAccessBlockConfiguration = nothing set at account level
aws s3control put-public-access-block --account-id <sandbox-id> --profile writ-sandbox \
  --public-access-block-configuration \
  BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=false,RestrictPublicBuckets=false
```

Restore the recorded state at teardown. With `s3_public_policy = false` the
bucket has Block Public Access disabled but no public grant. Whether that
finding counts as "a public S3 bucket" for A1.1 is a call to make and record
in the runbook, not one this module makes for you. Either way, sec. 7.3.3 means
an S3 petition is refused in Phase 2, so this fixture exercises only the
refusal path.

## Procedure

Run from `terraform/capture/`. Raw captures go to `.capture/` at the
repository root, which is gitignored. Nothing in it is ever committed.

**1. Apply.**

```bash
cp terraform.tfvars.example terraform.tfvars   # set sandbox_account_id; gitignored
terraform init
terraform plan                                 # read it: ~20 resources, all create
terraform apply
mkdir -p ../../.capture
```

**2. Wait for findings.** Change-triggered controls usually report within an
hour. Periodic ones can take up to a day. List what has arrived per target:

```bash
for arn in $(terraform output -json | python3 -c 'import json,sys; print(" ".join(v["value"] for v in json.load(sys.stdin).values()))'); do
  echo "== $arn"
  aws securityhub get-findings $P \
    --filters "{\"ResourceId\":[{\"Value\":\"$arn\",\"Comparison\":\"EQUALS\"}],\"ComplianceStatus\":[{\"Value\":\"FAILED\",\"Comparison\":\"EQUALS\"}],\"RecordState\":[{\"Value\":\"ACTIVE\",\"Comparison\":\"EQUALS\"}]}" \
    --query 'Findings[].[Compliance.SecurityControlId, Title]' --output text
done
```

Likely controls, to confirm against that output rather than trust: EC2.18 or
EC2.19 (security group), S3.8, plus S3.2 with a public policy (bucket), EC2.3
(volume), IAM.1 (policy). If IAM.1 never appears for the unattached policy,
set `attach_admin_policy = true`, apply, and wait again.

**3. Export one finding per class.** Pick the control from step 2:

```bash
aws securityhub get-findings $P \
  --filters '{"ResourceId":[{"Value":"<arn>","Comparison":"EQUALS"}],"RecordState":[{"Value":"ACTIVE","Comparison":"EQUALS"}]}' \
  --query "Findings[?Compliance.SecurityControlId=='<control>'] | [0]" --output json \
  > ../../.capture/security-group-open-ingress.json
```

Repeat for `s3-bucket-public.json`, `ebs-volume-unencrypted.json` and
`iam-policy-admin-star.json`. The names matter:
tests/test_injection_corpus.py and the corpus refer to them. `--output json`
is not optional: a profile defaulting to text or table would write something
that only fails to parse after the sandbox is gone.

**4. Capture the plan fixtures (sec. 5.3). Plan only, never apply.**

```bash
terraform plan -json -var remediate_security_group=true > ../../.capture/compliant-security-group-update.jsonl
terraform plan -json -var remediate_ebs_volume=true    > ../../.capture/noncompliant-ebs-volume-replace.jsonl
grep '"planned_change"' ../../.capture/*.jsonl
```

Expect exactly:

- compliant: `aws_security_group.open_ingress` with `"action":"update"`
- non-compliant: `aws_ebs_volume.unencrypted` and
  `aws_volume_attachment.unencrypted`, both with `"action":"replace"`

Any other planned change means the live state drifted from the configuration.
Stop and find out why before capturing. This is the only place in the project
where `-var` overrides are run against live state on purpose. The runbook's
warning about that pattern (A0.2) still applies: plan, read, never apply.

**5. Capture one CloudTrail event (sec. 5.3).** Event history is on by default
and free. Allow about 15 minutes after apply:

```bash
aws cloudtrail lookup-events $P \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AuthorizeSecurityGroupIngress \
  --max-results 1 --query 'Events[0].CloudTrailEvent' --output text \
  > ../../.capture/authorize-security-group-ingress.json
```

**6. Redact (sec. 5.4).** From the repository root:

```bash
python -m tools.redact_fixture \
  --account <sandbox-id>=123456789012 \
  --replace <identity-center-role-hash>=0000000000000000 \
  --replace <your-sso-user-name>=operator \
  .capture/security-group-open-ingress.json \
  tests/fixtures/findings/security-group-open-ingress.json
```

Destinations: `tests/fixtures/findings/` for the four findings,
`tests/fixtures/plans/` for the two `.jsonl` plans, `tests/fixtures/cloudtrail/`
for the event. The tool replaces account IDs, key and unique IDs, routable IP
addresses and emails. It refuses to write while any unrecognised 12-digit
sequence remains. Then **read every output file**: the tool only finds what it
was told to look for. Look in particular for an S3 `OwnerName`, Identity Center
user IDs (UUIDs next to `identitystore`), and any display name. Handle each
with `--replace`.

**7. Verify offline.** No network, no credentials (sec. 5.5):

```bash
env -u AWS_PROFILE -u AWS_ACCESS_KEY_ID -u AWS_SECRET_ACCESS_KEY -u AWS_SESSION_TOKEN \
  python -m unittest discover -s tests -v
```

The injection corpus (tests/test_injection_corpus.py) stops skipping as soon
as `tests/fixtures/findings/` holds a file. From then on a missing or
malformed fixture fails the run rather than skipping.

**8. Tear down (sec. 5.1, A1.4).**

```bash
terraform destroy
# restore account-level S3 Block Public Access if pre-flight changed it
aws resourcegroupstaggingapi get-resources --tag-filters Key=writ-capture $P  # expect none (can lag briefly)
aws configservice describe-configuration-recorders $P                         # expect []
aws securityhub describe-hub $P                                               # expect InvalidAccessException
aws ec2 describe-instances --filters Name=tag:writ-capture,Values=phase-1 \
  Name=instance-state-name,Values=pending,running,stopping,stopped $P --query 'Reservations[]'  # expect []

# IAM is global: the regional tagging query above never sees it. Each must be NoSuchEntity.
aws iam get-policy --policy-arn arn:aws:iam::<sandbox-id>:policy/writ-capture-admin-star --profile writ-sandbox
aws iam get-role --role-name writ-capture-admin-holder --profile writ-sandbox
aws iam get-role --role-name writ-capture-config --profile writ-sandbox
```

A surviving `writ-capture-admin-star` is a live `*` on `*` policy. Do not record
A1.4 until all three return `NoSuchEntity`.

**9. Record** the capture in docs/RUNBOOK.md under *Fixture capture*: date,
control IDs captured, the plan and event files, the destroy verification
output, the real cost, and whether the budget alarm fired (A0.5).
