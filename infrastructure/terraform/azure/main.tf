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
