variable "sandbox_account_id" {
  description = "Sandbox account ID. The provider refuses every other account."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.sandbox_account_id))
    error_message = "Account ID must be exactly 12 digits."
  }
}

variable "region" {
  description = "AWS region for the capture. Config and Security Hub are regional."
  type        = string
  default     = "ap-southeast-1"
}

variable "sandbox_profile" {
  description = "AWS CLI profile for the sandbox account"
  type        = string
}

variable "name_prefix" {
  description = "Prefix for every named resource, so teardown can be verified by name."
  type        = string
  default     = "writ-capture"
}

variable "instance_type" {
  description = "Host for the unencrypted volume. Must match ami_architecture."
  type        = string
  default     = "t4g.nano"
}

variable "ami_architecture" {
  description = "arm64 for Graviton types (t4g.*), x86_64 for t3.* and similar."
  type        = string
  default     = "arm64"

  validation {
    condition     = contains(["arm64", "x86_64"], var.ami_architecture)
    error_message = "ami_architecture must be arm64 or x86_64."
  }
}

variable "s3_public_policy" {
  description = <<-EOT
    Attach a bucket policy granting public s3:GetObject to the empty fixture
    bucket, making it public rather than merely unprotected. Requires the
    sandbox account's own S3 Block Public Access to be off first; see
    README.md pre-flight. False leaves the bucket with Block Public Access
    disabled but no public grant.
  EOT
  type        = bool
  default     = false
}

variable "attach_admin_policy" {
  description = <<-EOT
    Attach the "*" on "*" policy to a role nobody can assume. Leave false
    unless the unattached policy produced no finding; see README.md.
  EOT
  type        = bool
  default     = false
}

# The two remediation switches exist only to produce plan fixtures (sec. 5.3).
# Pass them to `terraform plan -json`, never to apply. See README.md.

variable "remediate_security_group" {
  description = "Plan-only. True removes the open ingress rule: an in-place update."
  type        = bool
  default     = false
}

variable "remediate_ebs_volume" {
  description = "Plan-only. True encrypts the fixture volume: a forced replacement."
  type        = bool
  default     = false
}
