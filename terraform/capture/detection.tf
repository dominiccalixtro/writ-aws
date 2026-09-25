# Detection services: AWS Config and Security Hub, sec. 4.4.2.
#
# Enabled only for the capture window and disabled by `terraform destroy`,
# so "disabled on teardown" is the same operation as every other teardown
# (sec. 4.4.4) rather than a manual step someone can forget.
#
# GuardDuty is deliberately absent. None of the four sec. 5.2 finding classes
# comes from it — all four are Security Hub controls evaluated through Config —
# so enabling it would add spend and findings without adding a fixture.

# sec. 4.4.2 — "an explicit resource-type list, never all supported types".
# One type per sec. 5.2 finding class, nothing else.
locals {
  recorded_resource_types = [
    "AWS::EC2::SecurityGroup", # over-permissive ingress
    "AWS::S3::Bucket",         # public bucket
    "AWS::EC2::Volume",        # unencrypted volume
    "AWS::IAM::Policy",        # "*" on "*"
  ]
}

# --- AWS Config -------------------------------------------------------------

# A role this module owns rather than the Config service-linked role: a
# service-linked role can outlive the module or refuse deletion while in use,
# and sec. 4.4.4 requires destroy to need no manual prerequisite.
data "aws_iam_policy_document" "config_trust" {
  statement {
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [var.sandbox_account_id]
    }
  }
}

resource "aws_iam_role" "config" {
  name               = "${var.name_prefix}-config"
  description        = "AWS Config recorder for Phase 1 fixture capture (sec. 5). Destroyed with the module."
  assume_role_policy = data.aws_iam_policy_document.config_trust.json
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

resource "aws_s3_bucket" "config_delivery" {
  bucket_prefix = "${var.name_prefix}-config-"
  force_destroy = true # sec. 4.4.4 — delivered snapshots must not block destroy
}

resource "aws_s3_bucket_public_access_block" "config_delivery" {
  bucket                  = aws_s3_bucket.config_delivery.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

data "aws_iam_policy_document" "config_delivery_bucket" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.config_delivery.arn,
      "${aws_s3_bucket.config_delivery.arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "config_delivery" {
  bucket     = aws_s3_bucket.config_delivery.id
  policy     = data.aws_iam_policy_document.config_delivery_bucket.json
  depends_on = [aws_s3_bucket_public_access_block.config_delivery]
}

# With a customer-managed recorder role, Config delivers as that role, so the
# write permission lives here rather than in a bucket policy grant.
data "aws_iam_policy_document" "config_delivery_role" {
  statement {
    actions   = ["s3:PutObject", "s3:PutObjectAcl"]
    resources = ["${aws_s3_bucket.config_delivery.arn}/AWSLogs/${var.sandbox_account_id}/*"]

    condition {
      test     = "StringLike"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.config_delivery.arn]
  }
}

resource "aws_iam_role_policy" "config_delivery" {
  name   = "delivery"
  role   = aws_iam_role.config.id
  policy = data.aws_iam_policy_document.config_delivery_role.json
}

resource "aws_config_configuration_recorder" "capture" {
  name     = var.name_prefix
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported                 = false
    include_global_resource_types = false
    resource_types                = local.recorded_resource_types

    recording_strategy {
      use_only = "INCLUSION_BY_RESOURCE_TYPES"
    }
  }
}

resource "aws_config_delivery_channel" "capture" {
  name           = var.name_prefix
  s3_bucket_name = aws_s3_bucket.config_delivery.bucket

  depends_on = [
    aws_config_configuration_recorder.capture,
    aws_iam_role_policy.config_delivery,
  ]
}

resource "aws_config_configuration_recorder_status" "capture" {
  name       = aws_config_configuration_recorder.capture.name
  is_enabled = true
  depends_on = [aws_config_delivery_channel.capture]
}

# --- Security Hub -----------------------------------------------------------

# Default standards off, then exactly one standard subscribed: the four
# finding classes are all AWS Foundational Security Best Practices controls.
resource "aws_securityhub_account" "capture" {
  enable_default_standards  = false
  control_finding_generator = "SECURITY_CONTROL"
  auto_enable_controls      = true

  depends_on = [aws_config_configuration_recorder_status.capture]
}

resource "aws_securityhub_standards_subscription" "fsbp" {
  standards_arn = "arn:aws:securityhub:${var.region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  depends_on    = [aws_securityhub_account.capture]
}
