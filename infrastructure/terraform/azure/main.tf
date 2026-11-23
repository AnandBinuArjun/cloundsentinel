terraform {
  required_version = ">= 1.7.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.14"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "lab" {
  name     = "${var.lab_prefix}-rg"
  location = var.azure_location
  tags = {
    ManagedBy   = "CloudSentinelLab"
    Environment = "isolated-sandbox"
    AutoDestroy = "required"
  }
}

resource "azurerm_storage_account" "lab_baseline" {
  #checkov:skip=CKV_AZURE_33:Ephemeral isolated sandbox storage account does not use Queue service logging
  #checkov:skip=CKV_AZURE_35:Sandbox lab evaluates storage posture without private VNet integration
  #checkov:skip=CKV_AZURE_43:Dynamic lab storage name uses validated prefix + unique suffix
  #checkov:skip=CKV_AZURE_59:Sandbox lab uses ARM reader validation before private endpoint lock-down
  #checkov:skip=CKV_AZURE_190:Sandbox lab evaluates public network posture via CloudSentinel rules
  #checkov:skip=CKV_AZURE_206:Ephemeral single-region sandbox lab uses LRS to minimize cost (<$5 budget)
  #checkov:skip=CKV2_AZURE_1:Ephemeral sandbox lab uses platform-managed keys to avoid Key Vault purge locks
  #checkov:skip=CKV2_AZURE_18:Ephemeral sandbox lab uses platform-managed keys
  #checkov:skip=CKV2_AZURE_33:Ephemeral sandbox lab does not provision private endpoints
  #checkov:skip=CKV2_AZURE_38:Ephemeral sandbox lab does not require soft-delete retention
  #checkov:skip=CKV2_AZURE_40:Sandbox lab evaluates shared access key posture via CloudSentinel rules
  #checkov:skip=CKV2_AZURE_41:Ephemeral sandbox lab does not require SAS expiration policy
  #checkov:skip=CKV2_AZURE_47:allow_nested_items_to_be_public is explicitly set to false below
  name                            = "${var.storage_account_prefix}${var.unique_suffix}"
  resource_group_name             = azurerm_resource_group.lab.name
  location                        = azurerm_resource_group.lab.location
  account_tier                    = "Standard"
  account_replication_type        = "LRS"
  https_traffic_only_enabled      = true
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false

  tags = {
    ManagedBy = "CloudSentinelLab"
  }
}

output "resource_group_name" {
  value = azurerm_resource_group.lab.name
}
