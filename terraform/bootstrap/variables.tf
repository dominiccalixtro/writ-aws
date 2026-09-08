variable "sandbox_account_id" {
  description = "AWS Account ID for the sandbox environment"
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.sandbox_account_id))
    error_message = "Account ID must be exactly 12 digits."
  }
}

variable "management_account_id" {
  description = "AWS Account ID for the management environment"
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.management_account_id))
    error_message = "Account ID must be exactly 12 digits."
  }
}

variable "region" {
  description = "AWS region"
  type        = string
  default     = "ap-southeast-1"
}

variable "broker_role_name" {
  description = "Name of the IAM role for the broker account"
  type        = string
}

variable "capability_role_arns" {
  description = "List of ARNs for IAM roles with required capabilities"
  type        = list(string)
  default     = []
}

variable "trail_log_bucket_arn" {
  description = "ARN of the S3 bucket for CloudTrail logs"
  type        = string
}

variable "sandbox_profile" {
  description = "AWS CLI profile for the sandbox account"
  type        = string
}

variable "management_profile" {
  description = "AWS CLI profile for the management account"
  type        = string
}

variable "broker_trusted_principal_arns" {
  description = <<-EOT
    Principals permitted to assume the broker role.
    Empty in Phases 0-2: no writ is served (IMPLEMENTATION_PLAN.md sec. 7.7, I8),
    so no principal should be able to assume this role. Populated in Phase 3.
  EOT
  type        = list(string)
  default     = []
}

variable "enable_quash_test_permission" {
  description = <<-EOT
    Temporarily grants the broker s3:ListAllMyBuckets and makes the role
    assumable, solely to exercise quash for A0.4. Without it the broker has
    zero permissions and is assumable by nobody, so there is nothing for
    quash to take away and no observable difference to record.

    MUST be false outside that exercise. See docs/RUNBOOK.md.
  EOT
  type        = bool
  default     = false
}