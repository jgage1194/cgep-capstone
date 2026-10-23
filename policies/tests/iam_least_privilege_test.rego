package compliance.iam_least_privilege_test

import data.compliance.iam_least_privilege
import rego.v1

scoped_statement := {
	"Effect": "Allow",
	"Action": "s3:PutObject",
	"Resource": "arn:aws:s3:::test-uploads/uploads/*",
}

role_policy(document) := {
	"address": "aws_iam_role_policy.example",
	"mode": "managed",
	"type": "aws_iam_role_policy",
	"change": {"after": {
		"policy": json.marshal(document),
	}},
}

iam_plan(statements) := {
	"resource_changes": [
		role_policy({
			"Version": "2012-10-17",
			"Statement": statements,
		}),
	],
}

# Passing fixtures must satisfy all three checks.
no_iam_denials(plan) if {
	count(iam_least_privilege.deny_iam_document) == 0 with input as plan
	count(iam_least_privilege.deny_iam_wildcard_actions) == 0 with input as plan
	count(iam_least_privilege.deny_iam_unrestricted_resources) == 0 with input as plan
}

test_scoped_data_permissions_pass if {
	plan := iam_plan([
		scoped_statement,
		{
			"Effect": "Allow",
			"Action": ["dynamodb:PutItem"],
			"Resource": [
				"arn:aws:dynamodb:us-east-1:123456789012:table/intake",
			],
		},
	])

	no_iam_denials(plan)
}

test_documented_operational_actions_pass if {
	every action in [
		"ec2:CreateNetworkInterface",
		"ec2:DescribeNetworkInterfaces",
		"ec2:DescribeSubnets",
		"ec2:DeleteNetworkInterface",
		"ec2:AssignPrivateIpAddresses",
		"ec2:UnassignPrivateIpAddresses",
		"xray:PutTraceSegments",
		"xray:PutTelemetryRecords",
	] {
		plan := iam_plan([{
			"Effect": "Allow",
			"Action": action,
			"Resource": "*",
		}])

		no_iam_denials(plan)
	}
}

test_wildcard_actions_fail if {
	every action in [
		"*",
		"s3:*",
		"dynamodb:*",
		"s3:Get*",
		"s3:GetObjec?",
		"ec2:*",
	] {
		statement := object.union(scoped_statement, {
			"Action": action,
		})

		failures := iam_least_privilege.deny_iam_wildcard_actions with input as iam_plan([statement])
		count(failures) == 1

		some msg in failures
		contains(msg, "GAP-07")
		contains(msg, action)
	}
}

test_unrestricted_data_resources_fail if {
	every action in [
		"s3:PutObject",
		"dynamodb:PutItem",
		"kms:Decrypt",
		"sqs:SendMessage",
	] {
		plan := iam_plan([{
			"Effect": "Allow",
			"Action": action,
			"Resource": "*",
		}])

		failures := iam_least_privilege.deny_iam_unrestricted_resources with input as plan
		count(failures) == 1
	}
}

# One allowed action must not exempt other actions in the statement.
test_mixed_operational_and_data_actions_fail if {
	plan := iam_plan([{
		"Effect": "Allow",
		"Action": ["xray:PutTraceSegments", "s3:PutObject"],
		"Resource": "*",
	}])

	failures := iam_least_privilege.deny_iam_unrestricted_resources with input as plan
	count(failures) == 1

	some msg in failures
	contains(msg, "s3:PutObject")
}

# Wildcard Deny statements restrict access rather than grant it.
test_wildcard_deny_passes if {
	plan := iam_plan([{
		"Effect": "Deny",
		"Action": "*",
		"Resource": "*",
	}])

	no_iam_denials(plan)
}

test_unsupported_allow_statements_fail if {
	every statement in [
		{
			"Effect": "Allow",
			"NotAction": "iam:*",
			"Resource": "*",
		},
		{
			"Effect": "Allow",
			"Action": "s3:PutObject",
			"NotResource": "arn:aws:s3:::excluded/*",
		},
		{"Effect": "Allow", "Resource": "*"},
		{"Effect": "Allow", "Action": "s3:PutObject"},
		{"Effect": "Allow", "Action": [], "Resource": "*"},
		{"Effect": "Allow", "Action": "s3:PutObject", "Resource": []},
		{"Effect": "Allow", "Action": null, "Resource": "*"},
	] {
		failures := iam_least_privilege.deny_iam_document with input as iam_plan([statement])
		count(failures) == 1
	}
}

test_unreadable_documents_fail if {
	every text in [
		null,
		"",
		"invalid-json",
		"{}",
		"{\"Statement\":[]}",
	] {
		policy := object.union(role_policy({}), {
			"change": {"after": {"policy": text}},
		})
		plan := {"resource_changes": [policy]}

		failures := iam_least_privilege.deny_iam_document with input as plan
		count(failures) == 1
	}
}

# IAM permits Statement to be a single object.
test_single_statement_object_passes if {
	no_iam_denials(iam_plan(scoped_statement))
}

test_wildcard_in_resource_array_fails if {
	statement := object.union(scoped_statement, {
		"Resource": ["arn:aws:s3:::test-uploads/*", "*"],
	})

	failures := iam_least_privilege.deny_iam_unrestricted_resources with input as iam_plan([statement])
	count(failures) == 1
}

test_module_policy_passes if {
	policy := object.union(
		role_policy({
			"Statement": [scoped_statement],
		}),
		{
			"address": "module.api.aws_iam_role_policy.data_access",
		},
	)

	no_iam_denials({"resource_changes": [policy]})
}

test_second_overbroad_policy_fails if {
	good := role_policy({"Statement": [scoped_statement]})

	bad := object.union(
		role_policy({
			"Statement": [{
				"Effect": "Allow",
				"Action": "dynamodb:*",
				"Resource": "*",
			}],
		}),
		{
			"address": "aws_iam_role_policy.second",
		},
	)

	plan := {"resource_changes": [good, bad]}

	failures := iam_least_privilege.deny_iam_wildcard_actions with input as plan
	count(failures) == 1

	some msg in failures
	contains(msg, "aws_iam_role_policy.second")
}

test_deleted_policy_passes if {
	policy := object.union(role_policy({}), {
		"change": {
			"actions": ["delete"],
			"after": null,
		},
	})

	no_iam_denials({"resource_changes": [policy]})
}

test_data_source_passes if {
	policy := object.union(role_policy({}), {"mode": "data"})

	no_iam_denials({"resource_changes": [policy]})
}

test_no_policies_passes if {
	no_iam_denials({"resource_changes": []})
}
