# METADATA
# title: Require Lambda connections to the workload VPC
# description: Requires every managed Lambda to use subnets and security groups belonging to the intended workload VPC.
# custom:
#   framework: HIPAA Security Rule
#   controls:
#     - "164.312(e)(1)"
#   gap: GAP-05
#   severity: high
#   remediation: Configure Lambda subnet and security group assignments in aws_vpc.main.
package compliance.lambda_vpc

import rego.v1

# Project-specific anchor: this is the workload's intended VPC.
lambda_workload_vpc_ids contains id if {
	some vpc in input.resource_changes
	vpc.mode == "managed"
	vpc.type == "aws_vpc"
	vpc.address == "aws_vpc.main"

	id := vpc.change.after.id
	is_string(id)
	id != ""
}

# Resolve each assigned network resource to the intended VPC.
lambda_network_resource_matches(resource_type, id, vpc_id) if {
	is_string(id)
	id != ""

	some resource in input.resource_changes
	resource.mode == "managed"
	resource.type == resource_type
	resource.change.after.id == id
	resource.change.after.vpc_id == vpc_id
}

lambda_uses_workload_vpc(function) if {
	some vpc_id in lambda_workload_vpc_ids
	some config in function.change.after.vpc_config

	is_array(config.subnet_ids)
	count(config.subnet_ids) > 0

	is_array(config.security_group_ids)
	count(config.security_group_ids) > 0

	every id in config.subnet_ids {
		lambda_network_resource_matches("aws_subnet", id, vpc_id)
	}

	every id in config.security_group_ids {
		lambda_network_resource_matches("aws_security_group", id, vpc_id)
	}
}

deny_lambda_vpc contains msg if {
	some function in input.resource_changes
	function.mode == "managed"
	function.type == "aws_lambda_function"
	function.change.after != null

	not lambda_uses_workload_vpc(function)

	msg := sprintf(
		"GAP-05 | HIPAA 164.312(e)(1): %s must have nonempty subnet and security group assignments that resolve to aws_vpc.main in this plan.",
		[function.address],
	)
}
