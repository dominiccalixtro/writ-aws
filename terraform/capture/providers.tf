terraform {
  required_version = ">= 1.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# Sandbox account only (sec. 5.1). allowed_account_ids makes the provider
# refuse to plan or apply against any other account, so a wrong profile —
# the management account's, say — fails before a single resource is read.
# Every resource in this module is deliberately insecure; that refusal is
# the difference between a fixture and an incident.
provider "aws" {
  region              = var.region
  profile             = var.sandbox_profile
  allowed_account_ids = [var.sandbox_account_id]

  default_tags {
    tags = {
      "writ-capture" = "phase-1"
    }
  }
}
