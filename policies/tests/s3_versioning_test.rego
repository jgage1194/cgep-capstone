package compliance.s3_versioning_test

import data.compliance.s3_versioning
import rego.v1

# Include an unfamiliar bucket to prove automatic policy coverage.
versioning_fixture_labels := ["uploads", "vault", "trail", "future"]

# Defaults to enabled versioning on every bucket.
# Overrides let tests change status or target independently.
versioning_plan(statuses, targets) := {
	"resource_changes": array.concat(buckets, configurations),
} if {
	buckets := [
	{
		"address": sprintf("aws_s3_bucket.%s", [label]),
		"mode": "managed",
		"type": "aws_s3_bucket",
		"change": {
			"actions": ["no-op"],
			"after": {"bucket": sprintf("test-%s", [label])},
		},
	} |
		some label in versioning_fixture_labels
	]

	configurations := [
	{
		"address": sprintf("aws_s3_bucket_versioning.%s", [label]),
		"mode": "managed",
		"type": "aws_s3_bucket_versioning",
		"change": {
			"actions": ["update"],
			"after": {
				"bucket": object.get(targets, label, sprintf("test-%s", [label])),
				"versioning_configuration": [{"status": status}],
			},
		},
	} |
		some label in versioning_fixture_labels
		status := object.get(statuses, label, "Enabled")
		status != "ABSENT"
	]
}

# Every bucket, including the unfamiliar one, has enabled versioning.
test_all_buckets_enabled_passes if {
	failures := s3_versioning.deny_s3_versioning with input as versioning_plan({}, {})
	count(failures) == 0
}

# Each bucket must fail independently when versioning is suspended.
test_each_bucket_suspended_fails if {
	every label in versioning_fixture_labels {
		fixture := versioning_plan({label: "Suspended"}, {})
		failures := s3_versioning.deny_s3_versioning with input as fixture
		count(failures) == 1
	}
}

# ABSENT tells the fixture builder to omit that versioning resource.
test_each_bucket_missing_versioning_fails if {
	every label in versioning_fixture_labels {
		fixture := versioning_plan({label: "ABSENT"}, {})
		failures := s3_versioning.deny_s3_versioning with input as fixture
		count(failures) == 1
	}
}

# Enabled versioning on another bucket must not satisfy the requirement.
test_each_bucket_wrong_target_fails if {
	every label in versioning_fixture_labels {
		fixture := versioning_plan({}, {label: "unrelated-bucket"})
		failures := s3_versioning.deny_s3_versioning with input as fixture
		count(failures) == 1
	}
}

# A null status cannot establish compliance.
test_each_bucket_null_status_fails if {
	every label in versioning_fixture_labels {
		fixture := versioning_plan({label: null}, {})
		failures := s3_versioning.deny_s3_versioning with input as fixture
		count(failures) == 1
	}
}

# No buckets means there is no versioning requirement to evaluate.
test_no_buckets_passes if {
	failures := s3_versioning.deny_s3_versioning with input as {"resource_changes": []}
	count(failures) == 0
}

# Buckets being deleted do not need a future versioning configuration.
test_deleted_bucket_passes if {
	fixture := {
		"resource_changes": [{
			"address": "aws_s3_bucket.retired",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["delete"],
				"after": null,
			},
		}],
	}

	failures := s3_versioning.deny_s3_versioning with input as fixture
	count(failures) == 0
}

# Data sources describe existing buckets; Terraform does not manage them.
test_bucket_data_source_passes if {
	fixture := {
		"resource_changes": [{
			"address": "data.aws_s3_bucket.external",
			"mode": "data",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["read"],
				"after": {"bucket": "external-bucket"},
			},
		}],
	}

	failures := s3_versioning.deny_s3_versioning with input as fixture
	count(failures) == 0
}

# Unknown bucket names must fail closed.
test_unknown_bucket_name_fails if {
	fixture := {
		"resource_changes": [{
			"address": "aws_s3_bucket.new",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["create"],
				"after": {"bucket": null},
				"after_unknown": {"bucket": true},
			},
		}],
	}

	failures := s3_versioning.deny_s3_versioning with input as fixture
	count(failures) == 1
}

# Module-qualified addresses must receive the same protection.
test_module_bucket_without_versioning_fails if {
	fixture := {
		"resource_changes": [{
			"address": "module.storage.aws_s3_bucket.attachments",
			"mode": "managed",
			"type": "aws_s3_bucket",
			"change": {
				"actions": ["create"],
				"after": {"bucket": "module-attachments"},
			},
		}],
	}

	failures := s3_versioning.deny_s3_versioning with input as fixture
	count(failures) == 1
}
