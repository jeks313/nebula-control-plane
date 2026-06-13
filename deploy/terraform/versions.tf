terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }

  # Recommended for any shared/real use: an ENCRYPTED remote backend, because
  # terraform state can contain sensitive values. Local state is fine for a
  # throwaway lab but is gitignored here. Example (fill in + uncomment):
  #
  # backend "s3" {
  #   bucket       = "your-tfstate-bucket"
  #   key          = "nebula-control-plane/lab.tfstate"
  #   region       = "ca-central-1"
  #   encrypt      = true            # SSE on the state object
  #   use_lockfile = true            # S3 native state locking
  # }
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
