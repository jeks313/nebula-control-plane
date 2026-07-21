terraform {
  required_version = ">= 1.10" # S3 native state locking (use_lockfile) needs >= 1.10

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }

  # The foundation stack's OWN state lives in the very bucket it creates, so it is a
  # one-time bootstrap:
  #   1. First apply with LOCAL state (comment this block out) to create the bucket + keys.
  #   2. Uncomment, then run `terraform init -migrate-state -backend-config=backend.hcl` to
  #      move foundation.tfstate into the bucket. From then on it is remote + locked.
  # The bucket name is NOT committed (so the repo can stay public): pass it via a gitignored
  # backend.hcl (copy from backend.hcl.example). The app stack uses the same bucket, other key.
  backend "s3" {
    key          = "nebula-control-plane/foundation.tfstate"
    region       = "ca-central-1"
    encrypt      = true
    use_lockfile = true
  }
}

# Credentials come from the environment / aws-vault — never hard-coded. See README.md.
provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project   = var.project
      Stack     = "foundation"
      ManagedBy = "terraform"
    }
  }
}
