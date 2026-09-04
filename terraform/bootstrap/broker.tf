# Trust policy: who may assume the broker role.
#
# Phases 0-2 serve no writs (IMPLEMENTATION_PLAN.md sec. 7.7, I8), so no
# principal should be able to assume this role. The explicit Deny below
# enforces that regardless of anything edited around it.
#
# PHASE 3: this Deny must be REMOVED, not merely supplemented. An explicit
# Deny wins over any Allow, so adding an Allow statement alongside it has
# no effect.
data "aws_iam_policy_document" "broker_trust" {
  dynamic "statement" {
    for_each = length(var.broker_trusted_principal_arns) > 0 ? [1] : []

    content {
      sid     = "AllowEnumeratedPrincipals"
      effect  = "Allow"
      actions = ["sts:AssumeRole"]

      principals {
        type        = "AWS"
        identifiers = var.broker_trusted_principal_arns
      }
    }
  }

  dynamic "statement" {
    for_each = length(var.broker_trusted_principal_arns) == 0 ? [1] : []

    content {
      sid     = "DenyAllUntilPhase3"
      effect  = "Deny"
      actions = ["sts:AssumeRole"]

      principals {
        type        = "AWS"
        identifiers = ["*"]
      }
    }
  }
}

data "aws_iam_policy_document" "broker_boundary" {
  dynamic "statement" {
    for_each = length(var.capability_role_arns) > 0 ? [1] : []

    content {
      sid       = "AssumeCapabilityRoles"
      effect    = "Allow"
      actions   = ["sts:AssumeRole"]
      resources = var.capability_role_arns
    }
  }

  # sec. 4.2.3 - Escalation.
  # Explicit Deny per sec. 4.2.4: absence of Allow is not sufficient.
  # These are the actions by which the broker could manufacture new
  # privilege - creating identities, minting credentials, or removing
  # its own boundary.
  statement {
    sid    = "DenyEscalation"
    effect = "Deny"

    actions = [
      "iam:CreateUser",
      "iam:CreateAccessKey",
      "iam:AttachUserPolicy",
      "iam:PutUserPolicy",
      "iam:DeleteRolePermissionsBoundary",
      "iam:PutRolePermissionsBoundary",
      "organizations:*",
      "account:*",
    ]

    resources = ["*"]
  }

  # sec. 4.2.3 - Evidence integrity (CloudTrail control plane).
  # The broker must not be able to erase or blind the record of its own
  # actions. Note UpdateTrail and PutEventSelectors are included: blinding
  # a trail by narrowing what it records is equivalent to deleting it.
  statement {
    sid    = "DenyEvidenceIntegrityCloudTrail"
    effect = "Deny"

    actions = [
      "cloudtrail:StopLogging",
      "cloudtrail:DeleteTrail",
      "cloudtrail:UpdateTrail",
      "cloudtrail:PutEventSelectors",
    ]

    resources = ["*"]
  }

  # sec. 4.2.3 - Evidence integrity (trail log bucket).
  #
  # "Lifecycle mutation" is read broadly: evidence can be destroyed without
  # calling any Delete API. A 1-day lifecycle expiration rule deletes objects
  # on a schedule, and suspending versioning removes the protection that makes
  # deletions recoverable. Object-level deletes are included because the broker
  # has no legitimate reason to write to a CloudTrail bucket at all - CloudTrail
  # writes via its own service principal, not via the broker.
  #
  # PHASE 3: trail_log_bucket_arn is a placeholder. This statement matches
  # nothing until the trail and bucket exist.
  statement {
    sid    = "DenyEvidenceIntegrityTrailBucket"
    effect = "Deny"

    actions = [
      "s3:DeleteBucket",
      "s3:PutLifecycleConfiguration",
      "s3:PutBucketVersioning",
      "s3:PutBucketPolicy",
      "s3:DeleteBucketPolicy",
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
      "s3:PutObjectRetention",
      "s3:PutObjectLegalHold",
    ]

    resources = [
      var.trail_log_bucket_arn,
      "${var.trail_log_bucket_arn}/*",
    ]
  }

  # sec. 4.2.3 - Boundary escape. Enforces I9.
  #
  # NotResource: deny sts:AssumeRole on anything NOT in the enumerated
  # capability role list. This is what makes the broker's only capability
  # "assume these specific roles" rather than "assume roles".
  #
  # With an empty list, no Deny statement is emitted - the boundary already
  # has no Allow for sts:AssumeRole, so nothing is assumable regardless.
  dynamic "statement" {
    for_each = length(var.capability_role_arns) > 0 ? [1] : []

    content {
      sid           = "DenyAssumeRoleOutsideCapabilityRoles"
      effect        = "Deny"
      actions       = ["sts:AssumeRole"]
      not_resources = var.capability_role_arns
    }
  }
}

# The boundary as a managed policy. A permissions boundary must be a
# managed policy ARN - it cannot be inline.
resource "aws_iam_policy" "broker_boundary" {
  name        = "${var.broker_role_name}-boundary"
  description = "Permissions boundary for the writ-aws broker role (sec. 4.2.2)"
  policy      = data.aws_iam_policy_document.broker_boundary.json
}

resource "aws_iam_role" "broker" {
  name                 = var.broker_role_name
  description          = "writ-aws broker. Sole credential holder (sec. 3.3). Assumable by nobody in Phases 0-2."
  assume_role_policy   = data.aws_iam_policy_document.broker_trust.json
  permissions_boundary = aws_iam_policy.broker_boundary.arn
  max_session_duration = 3600
}

# Identity policy: what the broker is actually granted.
#
# The boundary is a ceiling, not a grant - effective permissions are
# identity policy AND boundary. This document is the "identity policy" half.
#
# I9: sts:AssumeRole on enumerated capability roles, and nothing else.
# The broker never holds direct service permissions - the writ IS the
# scoped credential (ADR-001 D2).
data "aws_iam_policy_document" "broker_identity" {
  dynamic "statement" {
    for_each = length(var.capability_role_arns) > 0 ? [1] : []

    content {
      sid       = "AssumeCapabilityRoles"
      effect    = "Allow"
      actions   = ["sts:AssumeRole"]
      resources = var.capability_role_arns
    }
  }
}

resource "aws_iam_role_policy" "broker_identity" {
  count = length(var.capability_role_arns) > 0 ? 1 : 0

  name   = "${var.broker_role_name}-identity"
  role   = aws_iam_role.broker.id
  policy = data.aws_iam_policy_document.broker_identity.json
}