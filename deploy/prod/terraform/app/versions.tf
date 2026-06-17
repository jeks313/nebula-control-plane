terraform {
  required_version = ">= 1.10" # S3 native state locking (use_lockfile)
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }

  # The app stack's state, in the SAME bucket the foundation stack created (under a
  # different key). Fill in the bucket (foundation's `state_bucket` output) and run
  # `terraform init`. Until then the app uses local state (gitignored). The foundation
  # stack must be applied FIRST (this stack reads its remote state — see remote_state.tf).
  #
  backend "s3" {
    bucket       = "ncp-tfstate-123456789012"
    key          = "nebula-control-plane/app.tfstate"
    region       = "ca-central-1"
    encrypt      = true
    use_lockfile = true
  }
}

# Credentials are intentionally NOT configured here. The AWS provider picks them
# up from the environment / an aws-vault subprocess (see README.md). Never put an
# access key or secret in a .tf or .tfvars file.
provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = var.project
      ManagedBy = "terraform"
    }
  }
}
