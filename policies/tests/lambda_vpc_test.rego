package compliance.lambda_vpc_test

import data.compliance.lambda_vpc
import rego.v1

vpc := {
	"address": "aws_vpc.main",
	"mode": "managed",
	"type": "aws_vpc",
	"change": {"after": {"id": "vpc-workload"}},
}

subnet := {
	"address": "aws_subnet.private[0]",
	"mode": "managed",
	"type": "aws_subnet",
	"change": {"after": {
		"id": "subnet-private",
		"vpc_id": "vpc-workload",
	}},
}

security_group := {
	"address": "aws_security_group.lambda",
	"mode": "managed",
	"type": "aws_security_group",
	"change": {"after": {
		"id": "sg-lambda",
		"vpc_id": "vpc-workload",
	}},
}

config := {
	"subnet_ids": ["subnet-private"],
	"security_group_ids": ["sg-lambda"],
}

lambda_resource(settings) := {
	"address": "aws_lambda_function.example",
	"mode": "managed",
	"type": "aws_lambda_function",
	"change": {"after": {"vpc_config": settings}},
}

vpc_plan(settings, network) := {
	"resource_changes": array.concat(
		[lambda_resource(settings)],
		network,
	),
}

network := [vpc, subnet, security_group]

test_workload_vpc_passes if {
	plan := vpc_plan([config], network)

	count(lambda_vpc.deny_lambda_vpc) == 0 with input as plan
}

test_missing_vpc_block_fails if {
	function := object.union(lambda_resource([]), {
		"change": {"after": {"vpc_config": null}},
	})

	plan := {
		"resource_changes": array.concat([function], network),
	}

	failures := lambda_vpc.deny_lambda_vpc with input as plan
	count(failures) == 1

	some msg in failures
	contains(msg, "GAP-05")
	contains(msg, "aws_lambda_function.example")
}

test_empty_vpc_block_fails if {
	plan := vpc_plan([], network)

	failures := lambda_vpc.deny_lambda_vpc with input as plan
	count(failures) == 1
}

# Missing, empty, or unresolved assignments must fail.
test_incomplete_assignments_fail if {
	every settings in [
		{},
		{"subnet_ids": [], "security_group_ids": ["sg-lambda"]},
		{"subnet_ids": ["subnet-private"], "security_group_ids": []},
		{"subnet_ids": null, "security_group_ids": ["sg-lambda"]},
		{"subnet_ids": ["subnet-private"], "security_group_ids": null},
		{"subnet_ids": [null], "security_group_ids": ["sg-lambda"]},
		{"subnet_ids": ["subnet-private"], "security_group_ids": [null]},
	] {
		plan := vpc_plan([settings], network)

		failures := lambda_vpc.deny_lambda_vpc with input as plan
		count(failures) == 1
	}
}

test_subnet_in_wrong_vpc_fails if {
	wrong := object.union(subnet, {
		"change": {"after": {"vpc_id": "vpc-other"}},
	})

	plan := vpc_plan([config], [vpc, wrong, security_group])

	failures := lambda_vpc.deny_lambda_vpc with input as plan
	count(failures) == 1
}

test_security_group_in_wrong_vpc_fails if {
	wrong := object.union(security_group, {
		"change": {"after": {"vpc_id": "vpc-other"}},
	})

	plan := vpc_plan([config], [vpc, subnet, wrong])

	failures := lambda_vpc.deny_lambda_vpc with input as plan
	count(failures) == 1
}

test_unknown_subnet_id_fails if {
	settings := object.union(config, {
		"subnet_ids": ["subnet-unknown"],
	})

	plan := vpc_plan([settings], network)

	failures := lambda_vpc.deny_lambda_vpc with input as plan
	count(failures) == 1
}

test_unknown_security_group_id_fails if {
	settings := object.union(config, {
		"security_group_ids": ["sg-unknown"],
	})

	plan := vpc_plan([settings], network)

	failures := lambda_vpc.deny_lambda_vpc with input as plan
	count(failures) == 1
}

# One valid assignment must not hide an invalid assignment.
test_mixed_subnets_fail if {
	settings := object.union(config, {
		"subnet_ids": ["subnet-private", "subnet-unknown"],
	})

	plan := vpc_plan([settings], network)

	failures := lambda_vpc.deny_lambda_vpc with input as plan
	count(failures) == 1
}

test_mixed_security_groups_fail if {
	settings := object.union(config, {
		"security_group_ids": ["sg-lambda", "sg-unknown"],
	})

	plan := vpc_plan([settings], network)

	failures := lambda_vpc.deny_lambda_vpc with input as plan
	count(failures) == 1
}

test_missing_workload_vpc_fails if {
	plan := vpc_plan([config], [subnet, security_group])

	failures := lambda_vpc.deny_lambda_vpc with input as plan
	count(failures) == 1
}

test_wrong_vpc_anchor_fails if {
	other := object.union(vpc, {
		"address": "aws_vpc.other",
	})

	plan := vpc_plan([config], [other, subnet, security_group])

	failures := lambda_vpc.deny_lambda_vpc with input as plan
	count(failures) == 1
}

test_module_lambda_passes if {
	function := object.union(lambda_resource([config]), {
		"address": "module.api.aws_lambda_function.handler",
	})

	plan := {
		"resource_changes": array.concat([function], network),
	}

	count(lambda_vpc.deny_lambda_vpc) == 0 with input as plan
}

test_second_unattached_lambda_fails if {
	second := object.union(lambda_resource([]), {
		"address": "aws_lambda_function.second",
	})

	original := vpc_plan([config], network)
	plan := {
		"resource_changes": array.concat(
			original.resource_changes,
			[second],
		),
	}

	failures := lambda_vpc.deny_lambda_vpc with input as plan
	count(failures) == 1

	some msg in failures
	contains(msg, "aws_lambda_function.second")
}

test_deleted_lambda_passes if {
	function := object.union(lambda_resource([]), {
		"change": {
			"actions": ["delete"],
			"after": null,
		},
	})

	count(lambda_vpc.deny_lambda_vpc) == 0 with input as {
		"resource_changes": [function],
	}
}

test_lambda_data_source_passes if {
	function := object.union(lambda_resource([]), {
		"mode": "data",
	})

	count(lambda_vpc.deny_lambda_vpc) == 0 with input as {
		"resource_changes": [function],
	}
}

test_no_lambdas_passes if {
	count(lambda_vpc.deny_lambda_vpc) == 0 with input as {
		"resource_changes": [],
	}
}
