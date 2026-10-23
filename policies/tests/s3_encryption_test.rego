package compliance.s3_encryption_test

import data.compliance.s3_encryption
import rego.v1

key_arn := "arn:aws:kms:us-east-1:123456789012:key/test-key"

customer_key := {
	"address": "aws_kms_key.example",
	"mode": "managed",
	"type": "aws_kms_key",
	"change": {"after": {
		"arn": key_arn,
		"key_usage": "ENCRYPT_DECRYPT",
		"customer_master_key_spec": "SYMMETRIC_DEFAULT",
		"is_enabled": true,
	}},
}

kms_defaults := {
	"sse_algorithm": "aws:kms",
	"kms_master_key_id": key_arn,
}

# Build a bucket, its encryption configuration, and any supplied keys.
encryption_plan(tags, defaults, keys) := {
	"resource_changes": array.concat(
		[
			{
				"address": "aws_s3_bucket.example",
				"mode": "managed",
				"type": "aws_s3_bucket",
				"change": {"after": {
					"bucket": "test-bucket",
					"tags_all": tags,
				}},
			},
			{
				"address": "aws_s3_bucket_server_side_encryption_configuration.example",
				"mode": "managed",
				"type": "aws_s3_bucket_server_side_encryption_configuration",
				"change": {"after": {
					"bucket": "test-bucket",
					"rule": [{
						"apply_server_side_encryption_by_default": [defaults],
					}],
				}},
			},
		],
		keys,
	),
}

test_phi_customer_key_passes if {
	plan := encryption_plan({"DataClass": "phi"}, kms_defaults, [customer_key])
	count(s3_encryption.deny_s3_encryption) == 0 with input as plan
}

test_audit_sse_s3_passes if {
	plan := encryption_plan(
		{"DataClass": "audit"},
		{"sse_algorithm": "AES256"},
		[],
	)

	count(s3_encryption.deny_s3_encryption) == 0 with input as plan
}

test_phi_sse_s3_fails if {
	plan := encryption_plan(
		{"DataClass": "phi"},
		{"sse_algorithm": "AES256"},
		[],
	)

	failures := s3_encryption.deny_s3_encryption with input as plan
	count(failures) == 1

	some msg in failures
	contains(msg, "GAP-01")
	contains(msg, "aws_s3_bucket.example")
}

test_missing_classification_fails if {
	plan := encryption_plan({}, kms_defaults, [customer_key])

	failures := s3_encryption.deny_s3_encryption with input as plan
	count(failures) == 1
}

test_null_classification_fails if {
	plan := encryption_plan({"DataClass": null}, kms_defaults, [customer_key])

	failures := s3_encryption.deny_s3_encryption with input as plan
	count(failures) == 1
}

test_empty_classification_fails if {
	plan := encryption_plan({"DataClass": ""}, kms_defaults, [customer_key])

	failures := s3_encryption.deny_s3_encryption with input as plan
	count(failures) == 1
}

test_missing_encryption_fails if {
	original := encryption_plan({"DataClass": "audit"}, {}, [])
	plan := {"resource_changes": [original.resource_changes[0]]}

	failures := s3_encryption.deny_s3_encryption with input as plan
	count(failures) == 1
}

test_wrong_bucket_target_fails if {
	original := encryption_plan(
		{"DataClass": "audit"},
		{"sse_algorithm": "AES256"},
		[],
	)

	configuration := original.resource_changes[1]
	wrong_configuration := object.union(configuration, {
		"change": {
			"after": object.union(configuration.change.after, {
				"bucket": "another-bucket",
			}),
		},
	})

	plan := {
		"resource_changes": [
			original.resource_changes[0],
			wrong_configuration,
		],
	}

	failures := s3_encryption.deny_s3_encryption with input as plan
	count(failures) == 1
}

test_unsupported_algorithm_fails if {
	plan := encryption_plan(
		{"DataClass": "audit"},
		{"sse_algorithm": "invalid"},
		[],
	)

	failures := s3_encryption.deny_s3_encryption with input as plan
	count(failures) == 1
}

test_phi_without_managed_key_fails if {
	plan := encryption_plan({"DataClass": "phi"}, kms_defaults, [])

	failures := s3_encryption.deny_s3_encryption with input as plan
	count(failures) == 1
}

test_phi_aws_managed_alias_fails if {
	defaults := object.union(kms_defaults, {
		"kms_master_key_id": "alias/aws/s3",
	})

	plan := encryption_plan({"DataClass": "phi"}, defaults, [customer_key])

	failures := s3_encryption.deny_s3_encryption with input as plan
	count(failures) == 1
}

test_phi_null_key_reference_fails if {
	defaults := object.union(kms_defaults, {
		"kms_master_key_id": null,
	})

	plan := encryption_plan({"DataClass": "phi"}, defaults, [customer_key])

	failures := s3_encryption.deny_s3_encryption with input as plan
	count(failures) == 1
}

# Each key regression must independently trigger a denial.
test_unusable_customer_keys_fail if {
	every override in [
		{"is_enabled": false},
		{"key_usage": "SIGN_VERIFY"},
		{"customer_master_key_spec": "RSA_2048"},
		{"arn": "arn:aws:kms:us-east-1:123456789012:key/other-key"},
	] {
		key := object.union(customer_key, {
			"change": {
				"after": object.union(customer_key.change.after, override),
			},
		})

		plan := encryption_plan({"DataClass": "phi"}, kms_defaults, [key])

		failures := s3_encryption.deny_s3_encryption with input as plan
		count(failures) == 1
	}
}

test_deleted_customer_key_fails if {
	key := object.union(customer_key, {
		"change": {
			"actions": ["delete"],
			"after": null,
		},
	})

	plan := encryption_plan({"DataClass": "phi"}, kms_defaults, [key])

	failures := s3_encryption.deny_s3_encryption with input as plan
	count(failures) == 1
}

test_no_buckets_passes if {
	count(s3_encryption.deny_s3_encryption) == 0 with input as {
		"resource_changes": [],
	}
}

test_deleted_bucket_passes if {
	original := encryption_plan({"DataClass": "phi"}, {}, [])

	bucket := object.union(original.resource_changes[0], {
		"change": {
			"actions": ["delete"],
			"after": null,
		},
	})

	count(s3_encryption.deny_s3_encryption) == 0 with input as {
		"resource_changes": [bucket],
	}
}

test_bucket_data_source_passes if {
	original := encryption_plan({}, {}, [])

	bucket := object.union(original.resource_changes[0], {
		"mode": "data",
	})

	count(s3_encryption.deny_s3_encryption) == 0 with input as {
		"resource_changes": [bucket],
	}
}
