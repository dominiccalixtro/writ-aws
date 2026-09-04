# Organizations lives in the management account only.
data "aws_organizations_organization" "current" {
  provider = aws.management
}

# sec. 4.3.1 requires the quash SCP attached to the sandbox account's OU.
# The sandbox currently sits directly under Root; SCPs cannot be attached
# to Root for this purpose without affecting every account in the org,
# including the management account.
resource "aws_organizations_organizational_unit" "sandbox" {
  provider = aws.management

  name      = "writ-sandbox"
  parent_id = data.aws_organizations_organization.current.roots[0].id
}

# sec. 4.3 - Quash. Denies the broker role all actions.
#
# Scoped to the broker role's ARN via a condition, NOT to all principals -
# quashing must not lock the operator out of the sandbox.
#
# No provider argument: policy documents are generated locally, not fetched
# from AWS, so they do not belong to an account.
data "aws_iam_policy_document" "quash" {
  statement {
    sid       = "QuashBrokerRole"
    effect    = "Deny"
    actions   = ["*"]
    resources = ["*"]

    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = ["arn:aws:iam::${var.sandbox_account_id}:role/${var.broker_role_name}"]
    }
  }
}

# Created DETACHED. sec. 4.3.1 requires the SCP to exist and be "capable of"
# denying the broker; sec. 4.3.2 requires quash to be a single command.
# Attaching it IS the quash. See docs/RUNBOOK.md.
#
# The sandbox account must be moved into the OU by CLI before this SCP can
# affect it - see terraform/bootstrap/README.md for the move-account command.
resource "aws_organizations_policy" "quash" {
  provider = aws.management

  name        = "writ-quash-broker"
  description = "Denies the writ-aws broker role all actions. Attach to quash."
  type        = "SERVICE_CONTROL_POLICY"
  content     = data.aws_iam_policy_document.quash.json
}