package cloudsentinel.azure.storage

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    after := resource.change.after
    after.allow_nested_items_to_be_public == true
    msg := sprintf("AZ-STG-001: %s must disable anonymous public blob access", [resource.address])
}

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "azurerm_storage_account"
    after := resource.change.after
    after.min_tls_version != "TLS1_2"
    msg := sprintf("AZ-STG-002: %s must enforce min_tls_version = TLS1_2", [resource.address])
}
