# Fixtures

Captured once from a live sandbox account (docs/IMPLEMENTATION_PLAN.md sec. 5),
redacted (sec. 5.4), committed here, and the sandbox destroyed immediately
after. Nothing captured here is ever re-captured casually — capturing means a
sandbox account is live. Procedure: `terraform/capture/README.md`.

Required at minimum (sec. 5.2-5.3), at these paths — the injection corpus
refers to the findings by name:

| Path | What |
|---|---|
| `findings/security-group-open-ingress.json` | over-permissive security group ingress (ASFF) |
| `findings/s3-bucket-public.json` | public S3 bucket (ASFF) |
| `findings/ebs-volume-unencrypted.json` | unencrypted EBS volume (ASFF) |
| `findings/iam-policy-admin-star.json` | IAM policy granting `*` on `*` (ASFF) |
| `plans/compliant-security-group-update.jsonl` | `terraform plan -json`, compliant remediation |
| `plans/noncompliant-ebs-volume-replace.jsonl` | `terraform plan -json`, non-compliant remediation |
| `cloudtrail/authorize-security-group-ingress.json` | one CloudTrail event record |

Each finding file is one ASFF finding object, not a `get-findings` response.

`injection/corpus.json` is the exception: it is **authored, not captured**. It
holds the sec. 9.3 injection corpus as petition fixtures (sec. 2, sec. 9.3.1):
the hostile text planted in a captured finding, and the petition a fully
compromised agent plane would emit by obeying it. Its petitions take every
identifier from the finding they answer, so it carries none of its own.

A test (sec. 5.4) asserts no fixture contains the operator's real 12-digit
AWS account ID.
