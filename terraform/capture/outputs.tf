# The resource ARNs Security Hub findings carry in Resources[].Id. Each is the
# filter for exporting that target's finding; see README.md.

output "security_group_arn" {
  description = "Target of the over-permissive ingress finding."
  value       = aws_security_group.open_ingress.arn
}

output "bucket_arn" {
  description = "Target of the public bucket finding. No account field (sec. 7.3.3)."
  value       = aws_s3_bucket.public.arn
}

output "volume_arn" {
  description = "Target of the unencrypted volume finding."
  value       = aws_ebs_volume.unencrypted.arn
}

output "admin_policy_arn" {
  description = "Target of the * on * policy finding."
  value       = aws_iam_policy.admin_star.arn
}
