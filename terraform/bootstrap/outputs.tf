output "sandbox_ou_id" {
  description = "OU ID. Needed for move-account and for attaching the quash SCP."
  value       = aws_organizations_organizational_unit.sandbox.id
}

output "quash_policy_id" {
  description = "Quash SCP ID. Attach to the sandbox OU to quash the broker."
  value       = aws_organizations_policy.quash.id
}

output "broker_role_arn" {
  description = "Broker role ARN. Needed for A0.3 simulate-principal-policy."
  value       = aws_iam_role.broker.arn
}

output "broker_boundary_policy_arn" {
  description = "Permissions boundary policy ARN."
  value       = aws_iam_policy.broker_boundary.arn
}