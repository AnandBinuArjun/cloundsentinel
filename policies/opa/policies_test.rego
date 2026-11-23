package cloudsentinel.tests

import data.cloudsentinel.aws.s3 as aws_s3
import data.cloudsentinel.azure.storage as az_storage
import data.cloudsentinel.terraform.guardrails as tf_guard

test_deny_public_s3_block_disabled {
    msgs := aws_s3.deny with input as {
        "resource_changes": [{
            "address": "aws_s3_bucket_public_access_block.bad",
            "type": "aws_s3_bucket_public_access_block",
            "change": {"after": {"block_public_acls": false, "restrict_public_buckets": true}}
        }]
    }
    count(msgs) == 1
}

test_allow_secure_s3_block {
    msgs := aws_s3.deny with input as {
        "resource_changes": [{
            "address": "aws_s3_bucket_public_access_block.good",
            "type": "aws_s3_bucket_public_access_block",
            "change": {"after": {"block_public_acls": true, "restrict_public_buckets": true}}
        }]
    }
    count(msgs) == 0
}

test_deny_azure_public_blob_and_weak_tls {
    msgs := az_storage.deny with input as {
        "resource_changes": [{
            "address": "azurerm_storage_account.bad",
            "type": "azurerm_storage_account",
            "change": {"after": {"allow_nested_items_to_be_public": true, "min_tls_version": "TLS1_0"}}
        }]
    }
    count(msgs) == 2
}

test_deny_unrestricted_ssh_ingress {
    msgs := tf_guard.deny with input as {
        "resource_changes": [{
            "address": "aws_security_group_rule.ssh_open",
            "type": "aws_security_group_rule",
            "change": {"after": {"type": "ingress", "from_port": 22, "to_port": 22, "cidr_blocks": ["0.0.0.0/0"]}}
        }]
    }
    count(msgs) == 1
}
