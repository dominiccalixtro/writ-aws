terraform {
  required_version = ">= 1.7"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
  }
}

# Default provider — sandbox account.
# Deliberately the default so a resource that omits an explicit provider
# argument lands in the sandbox rather than the management account.
provider "aws" {
  region  = var.region
  profile = var.sandbox_profile
}

# Management account — Organizations, the sandbox OU, and the quash SCP.
provider "aws" {
  alias   = "management"
  region  = var.region
  profile = var.management_profile
}