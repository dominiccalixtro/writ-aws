# Fixtures

Empty until Phase 1 (docs/IMPLEMENTATION_PLAN.md sec. 5). Fixtures are captured
once from a live sandbox account, redacted (sec. 5.4), committed here, and the
sandbox is destroyed immediately after. Nothing in this directory is ever
re-captured casually — capturing means a sandbox account is live.

Required at minimum (sec. 5.2-5.3):

- an over-permissive security group ingress rule (ASFF finding)
- a public S3 bucket (ASFF finding)
- an unencrypted EBS volume (ASFF finding)
- an IAM policy granting `*` on `*` (ASFF finding)
- `terraform plan -json` output: one compliant remediation, one non-compliant
- one CloudTrail event record

A test (sec. 5.4) asserts no fixture contains the operator's real 12-digit
AWS account ID.
