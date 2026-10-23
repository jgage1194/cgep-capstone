package compliance.dynamodb_encryption_test

import data.compliance.dynamodb_encryption
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

encryption := [{
	"enabled": true,
	"kms_key_arn": key_arn,
}]

table := {
	"address": "aws_dynamodb_table.example",
	"mode": "managed",
	"type": "aws_dynamodb_table",
	"change": {"after": {
		"server_side_encryption": encryption,
	}},
}

# Keep table settings and key fixtures independently adjustable.
dynamodb_plan(settings, keys) := {
	"resource_changes": array.concat(
		[
			object.union(table, {
				"change": {"after": {
					"server_side_encryption": settings,
				}},
			}),
		],
		keys,
	),
}

test_customer_key_passes if {
	plan := dynamodb_plan(encryption, [customer_key])

	count(dynamodb_encryption.deny_dynamodb_encryption) == 0 with input as plan
}

# Each incomplete or disabled encryption configuration must fail.
test_invalid_encryption_settings_fail if {
	every settings in [
		[],
		[{}],
		[{"enabled": false, "kms_key_arn": key_arn}],
		[{"enabled": true}],
		[{"enabled": true, "kms_key_arn": null}],
		[{"enabled": true, "kms_key_arn": ""}],
	] {
		plan := dynamodb_plan(settings, [customer_key])

		failures := dynamodb_encryption.deny_dynamodb_encryption with input as plan
		count(failures) == 1
	}
}

test_missing_encryption_block_fails if {
	# Remove change first so object.union cannot retain its old contents.
	unencrypted := object.union(object.remove(table, {"change"}), {
		"change": {"after": {}},
	})

	plan := {"resource_changes": [unencrypted, customer_key]}

	failures := dynamodb_encryption.deny_dynamodb_encryption with input as plan
	count(failures) == 1

	some msg in failures
	contains(msg, "GAP-02")
	contains(msg, "aws_dynamodb_table.example")
}

test_key_missing_from_plan_fails if {
	plan := dynamodb_plan(encryption, [])

	failures := dynamodb_encryption.deny_dynamodb_encryption with input as plan
	count(failures) == 1
}

test_aws_managed_alias_fails if {
	plan := dynamodb_plan(
		[
			{"enabled": true, "kms_key_arn": "alias/aws/dynamodb"},
		],
		[customer_key],
	)

	failures := dynamodb_encryption.deny_dynamodb_encryption with input as plan
	count(failures) == 1
}

# Check disabled, unsuitable, and mismatched keys independently.
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

		plan := dynamodb_plan(encryption, [key])

		failures := dynamodb_encryption.deny_dynamodb_encryption with input as plan
		count(failures) == 1
	}
}

test_deleted_key_fails if {
	key := object.union(customer_key, {
		"change": {
			"actions": ["delete"],
			"after": null,
		},
	})

	plan := dynamodb_plan(encryption, [key])

	failures := dynamodb_encryption.deny_dynamodb_encryption with input as plan
	count(failures) == 1
}

# One compliant table must not hide another unprotected table.
test_second_unprotected_table_fails if {
	second := object.union(object.remove(table, {"change"}), {
		"address": "module.storage.aws_dynamodb_table.second",
		"change": {"after": {}},
	})

	plan := {"resource_changes": [table, customer_key, second]}

	failures := dynamodb_encryption.deny_dynamodb_encryption with input as plan
	count(failures) == 1

	some msg in failures
	contains(msg, "module.storage.aws_dynamodb_table.second")
}

test_module_table_passes if {
	nested := object.union(table, {
		"address": "module.storage.aws_dynamodb_table.example",
	})

	plan := {"resource_changes": [nested, customer_key]}

	count(dynamodb_encryption.deny_dynamodb_encryption) == 0 with input as plan
}

test_deleted_table_passes if {
	deleted := object.union(table, {
		"change": {
			"actions": ["delete"],
			"after": null,
		},
	})

	plan := {"resource_changes": [deleted]}

	count(dynamodb_encryption.deny_dynamodb_encryption) == 0 with input as plan
}

test_table_data_source_passes if {
	external := object.union(object.remove(table, {"change"}), {
		"mode": "data",
		"change": {"after": {}},
	})

	plan := {"resource_changes": [external]}

	count(dynamodb_encryption.deny_dynamodb_encryption) == 0 with input as plan
}

test_no_tables_passes if {
	count(dynamodb_encryption.deny_dynamodb_encryption) == 0 with input as {
		"resource_changes": [],
	}
}
