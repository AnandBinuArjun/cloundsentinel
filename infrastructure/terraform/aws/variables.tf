variable "aws_region" {
  type        = string
  default     = "us-east-1"
  description = "AWS region for the isolated CloudSentinel sandbox lab."
}

variable "lab_prefix" {
  type        = string
  default     = "cloudsentinel-lab"
  description = "Prefix applied to sandbox lab resources."
}

variable "unique_suffix" {
  type        = string
  description = "Globally unique lowercase suffix for S3 bucket naming."
}

variable "trusted_principal_arn" {
  type        = string
  description = "IAM principal ARN authorized to assume the CloudSentinel read-only role."
}

variable "external_id" {
  type        = string
  sensitive   = true
  description = "Tenant-specific ExternalId required for STS AssumeRole."
}
