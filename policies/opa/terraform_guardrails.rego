package cloudsentinel.terraform.guardrails

deny[msg] {
    resource := input.resource_changes[_]
    resource.type == "aws_security_group_rule"
    after := resource.change.after
    after.type == "ingress"
    after.from_port <= 22
    after.to_port >= 22
    cidr := after.cidr_blocks[_]
    cidr == "0.0.0.0/0"
    msg := sprintf("AWS-EC2-001: %s exposes SSH port 22 to 0.0.0.0/0", [resource.address])
}

deny[msg] {
    resource := input.resource_changes[_]
    after := resource.change.after
    after.tags
    not after.tags.ManagedBy
    msg := sprintf("TAG-001: %s must include a ManagedBy ownership tag", [resource.address])
}
