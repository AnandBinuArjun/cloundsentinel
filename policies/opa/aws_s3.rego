package cloudsentinel.aws.s3

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    after := resource.change.after
    not after.block_public_acls
    msg := sprintf("AWS-S3-001: %s must set block_public_acls = true", [resource.address])
}

deny contains msg if {
    resource := input.resource_changes[_]
    resource.type == "aws_s3_bucket_public_access_block"
    after := resource.change.after
    not after.restrict_public_buckets
    msg := sprintf("AWS-S3-001: %s must set restrict_public_buckets = true", [resource.address])
}
