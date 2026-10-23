# METADATA
# title: Require S3 encryption based on data classification
# description: Requires explicit encryption for all buckets and customer-managed KMS keys for PHI.
# custom:
#   framework: HIPAA Security Rule
#   controls:
#     - "164.312(a)(2)(iv)"
#   gap: GAP-01
#   severity: high
#   remediation: Configure bucket encryption and use a customer-managed KMS key for PHI.
package compliance.s3_encryption

import rego.v1

# Discover every managed bucket remaining in the plan.
s3_encryption_buckets contains bucket if {
	some bucket in input.resource_changes
	bucket.mode == "managed"
	bucket.type == "aws_s3_bucket"
	bucket.change.after != null
}

# tags_all includes provider defaults and resource-level overrides.
s3_encryption_classified(bucket) if {
	classification := bucket.change.after.tags_all.DataClass
	is_string(classification)
	classification != ""
}

# Find the encryption settings associated with this bucket.
s3_encryption_defaults(bucket) := {defaults |
	name := bucket.change.after.bucket
	is_string(name)
	name != ""

	some configuration in input.resource_changes
	configuration.mode == "managed"
	configuration.type == "aws_s3_bucket_server_side_encryption_configuration"
	configuration.change.after.bucket == name

	some rule in configuration.change.after.rule
	some defaults in rule.apply_server_side_encryption_by_default
}

# Accept explicit SSE-S3 or SSE-KMS as the general baseline.
s3_encryption_configured(bucket) if {
	some defaults in s3_encryption_defaults(bucket)
	defaults.sse_algorithm in {"AES256", "aws:kms"}
}

# Match the configured key ARN to a customer-managed key in this plan.
# An AWS-managed key or an arbitrary nonempty ARN does not satisfy this.
s3_encryption_uses_customer_key(bucket) if {
	some defaults in s3_encryption_defaults(bucket)
	defaults.sse_algorithm == "aws:kms"

	key_arn := defaults.kms_master_key_id
	is_string(key_arn)
	key_arn != ""

	some key in input.resource_changes
	key.mode == "managed"
	key.type == "aws_kms_key"
	key.change.after != null
	key.change.after.arn == key_arn
	key.change.after.key_usage == "ENCRYPT_DECRYPT"
	key.change.after.customer_master_key_spec == "SYMMETRIC_DEFAULT"
	key.change.after.is_enabled == true
}

# Missing classification must not bypass the PHI requirement.
deny_s3_encryption contains msg if {
	some bucket in s3_encryption_buckets
	not s3_encryption_classified(bucket)

	msg := sprintf(
		"GRC baseline: %s must have a known, nonempty DataClass tag.",
		[bucket.address],
	)
}

deny_s3_encryption contains msg if {
	some bucket in s3_encryption_buckets
	not s3_encryption_configured(bucket)

	msg := sprintf(
		"GRC baseline: %s must have an explicit SSE-S3 or SSE-KMS encryption configuration.",
		[bucket.address],
	)
}

deny_s3_encryption contains msg if {
	some bucket in s3_encryption_buckets
	bucket.change.after.tags_all.DataClass == "phi"
	not s3_encryption_uses_customer_key(bucket)

	msg := sprintf(
		"GAP-01 | HIPAA 164.312(a)(2)(iv): %s contains PHI and must use SSE-KMS with an enabled customer-managed symmetric encryption key defined in this plan.",
		[bucket.address],
	)
}
