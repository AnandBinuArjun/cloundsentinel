variable "azure_location" {
  type        = string
  default     = "eastus"
  description = "Azure region for the isolated CloudSentinel sandbox lab."
}

variable "lab_prefix" {
  type        = string
  default     = "cloudsentinel-lab"
  description = "Prefix for sandbox resource group naming."
}

variable "storage_account_prefix" {
  type        = string
  default     = "stcsentlab"
  description = "Lowercase alphanumeric prefix for Azure Storage Account."
}

variable "unique_suffix" {
  type        = string
  description = "Lowercase alphanumeric suffix (4-8 chars) for unique storage naming."
}
