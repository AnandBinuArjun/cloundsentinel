terraform {
  required_version = ">= 1.7.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      ManagedBy   = "CloudSentinelLab"
      Environment = "isolated-sandbox"
      AutoDestroy = "required"
    }
  }
}

# Read-only cross-account assessment role for CloudSentinel
resource "aws_iam_role" "cloudsentinel_readonly" {
  name = "${var.lab_prefix}-readonly-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = var.trusted_principal_arn
        }
        Action = "sts:AssumeRole"
        Condition = {
          StringEquals = {
            "sts:ExternalId" = var.external_id
          }
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "security_audit" {
  role       = aws_iam_role.cloudsentinel_readonly.name
  policy_arn = "arn:aws:iam::aws:policy/SecurityAudit"
}

# Controlled secure baseline S3 bucket for lab validation
resource "aws_s3_bucket" "lab_baseline" {
  bucket        = "${var.lab_prefix}-baseline-${var.unique_suffix}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "lab_baseline" {
  bucket                  = aws_s3_bucket.lab_baseline.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lab_baseline" {
  bucket = aws_s3_bucket.lab_baseline.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

output "cloudsentinel_role_arn" {
  value       = aws_iam_role.cloudsentinel_readonly.arn
  description = "Read-only IAM role ARN to register in CloudSentinel."
}
