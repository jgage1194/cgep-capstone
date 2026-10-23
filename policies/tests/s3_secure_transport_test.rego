package compliance.s3_secure_transport_test

import rego.v1
import data.compliance.s3_secure_transport

# A complete deny covering the bucket and all its objects.
tls_statement := {
	"Effect": "Deny",
	"Principal": "*",
	"Action": "s3:*",
	"Resource": [
		"arn:aws:s3:::test-bucket",
		"arn:aws:s3:::test-bucket/*",
	],
	"Condition": {
		"Bool": {
			"aws:SecureTransport": "false",
		},
	},
}

# Minimal managed bucket fixture.
tls_bucket := {
	"address": "aws_s3_bucket.example",
	"mode": "managed",
	"type": "aws_s3_bucket",
	"change": {
		"actions": ["no-op"],
		"after": {
			"bucket": "test-bucket",
			"arn": "arn:aws:s3:::test-bucket",
		},
	},
}

# Build a Terraform plan containing the bucket and its policy.
tls_plan(statement) := {
	"resource_changes": [
		tls_bucket,
		{
			"address": "aws_s3_bucket_policy.example",
			"mode": "managed",
			"type": "aws_s3_bucket_policy",
			"change": {
				"actions": ["update"],
				"after": {
					"bucket": "test-bucket",
					"policy": json.marshal({
						"Version": "2012-10-17",
						"Statement": [statement],
					}),
				},
			},
		},
	],
}

test_complete_tls_deny_passes if {
	count(s3_secure_transport.deny_s3_secure_transport) == 0 with input as tls_plan(tls_statement)
}

# IAM also accepts an AWS principal object and an action array.
test_principal_object_and_action_array_pass if {
	statement := object.union(tls_statement, {
		"Principal": {"AWS": ["*"]},
		"Action": ["s3:*"],
	})

	count(s3_secure_transport.deny_s3_secure_transport) == 0 with input as tls_plan(statement)
}

test_boolean_false_passes if {
	statement := object.union(tls_statement, {
		"Condition": {"Bool": {"aws:SecureTransport": false}},
	})

	count(s3_secure_transport.deny_s3_secure_transport) == 0 with input as tls_plan(statement)
}

test_wildcard_action_passes if {
	statement := object.union(tls_statement, {"Action": "*"})

	count(s3_secure_transport.deny_s3_secure_transport) == 0 with input as tls_plan(statement)
}

test_missing_bucket_policy_fails if {
	plan := {"resource_changes": [tls_bucket]}

	failures := s3_secure_transport.deny_s3_secure_transport with input as plan
	count(failures) == 1

	some msg in failures
	contains(msg, "GAP-03")
	contains(msg, "aws_s3_bucket.example")
}

test_allow_instead_of_deny_fails if {
	statement := object.union(tls_statement, {"Effect": "Allow"})

	failures := s3_secure_transport.deny_s3_secure_transport with input as tls_plan(statement)
	count(failures) == 1
}

test_restricted_principal_fails if {
	statement := object.union(tls_statement, {
		"Principal": {"AWS": "arn:aws:iam::123456789012:root"},
	})

	failures := s3_secure_transport.deny_s3_secure_transport with input as tls_plan(statement)
	count(failures) == 1
}

test_partial_action_fails if {
	statement := object.union(tls_statement, {"Action": "s3:GetObject"})

	failures := s3_secure_transport.deny_s3_secure_transport with input as tls_plan(statement)
	count(failures) == 1
}

test_missing_object_resource_fails if {
	statement := object.union(tls_statement, {
		"Resource": "arn:aws:s3:::test-bucket",
	})

	failures := s3_secure_transport.deny_s3_secure_transport with input as tls_plan(statement)
	count(failures) == 1
}

test_missing_bucket_resource_fails if {
	statement := object.union(tls_statement, {
		"Resource": "arn:aws:s3:::test-bucket/*",
	})

	failures := s3_secure_transport.deny_s3_secure_transport with input as tls_plan(statement)
	count(failures) == 1
}

test_wrong_transport_condition_fails if {
	statement := object.union(tls_statement, {
		"Condition": {"Bool": {"aws:SecureTransport": "true"}},
	})

	failures := s3_secure_transport.deny_s3_secure_transport with input as tls_plan(statement)
	count(failures) == 1
}

test_missing_transport_condition_fails if {
	statement := object.remove(tls_statement, {"Condition"})

	failures := s3_secure_transport.deny_s3_secure_transport with input as tls_plan(statement)
	count(failures) == 1
}

test_policy_for_another_bucket_fails if {
	original := tls_plan(tls_statement)
	policy := original.resource_changes[1]

	wrong_policy := object.union(policy, {
		"change": {
			"actions": ["update"],
			"after": object.union(policy.change.after, {
				"bucket": "another-bucket",
			}),
		},
	})

	plan := {"resource_changes": [tls_bucket, wrong_policy]}

	failures := s3_secure_transport.deny_s3_secure_transport with input as plan
	count(failures) == 1
}

# A compliant bucket must not hide a second unprotected bucket.
test_second_unprotected_bucket_fails if {
	original := tls_plan(tls_statement)

	second_bucket := object.union(tls_bucket, {
		"address": "module.storage.aws_s3_bucket.attachments",
		"change": {
			"actions": ["create"],
			"after": {
				"bucket": "another-bucket",
				"arn": "arn:aws:s3:::another-bucket",
			},
		},
	})

	plan := {
		"resource_changes": array.concat(
			original.resource_changes,
			[second_bucket],
		),
	}

	failures := s3_secure_transport.deny_s3_secure_transport with input as plan
	count(failures) == 1

	some msg in failures
	contains(msg, "module.storage.aws_s3_bucket.attachments")
}

test_no_buckets_passes if {
	count(s3_secure_transport.deny_s3_secure_transport) == 0 with input as {"resource_changes": []}
}

test_deleted_bucket_passes if {
	bucket := object.union(tls_bucket, {
		"change": {
			"actions": ["delete"],
			"after": null,
		},
	})

	count(s3_secure_transport.deny_s3_secure_transport) == 0 with input as {"resource_changes": [bucket]}
}

test_bucket_data_source_passes if {
	bucket := object.union(tls_bucket, {"mode": "data"})

	count(s3_secure_transport.deny_s3_secure_transport) == 0 with input as {"resource_changes": [bucket]}
}