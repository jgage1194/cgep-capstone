# METADATA
# title: Require customer-managed encryption for DynamoDB tables
# description: Rejects tables without an enabled customer-managed symmetric encryption key in the plan.
# custom:
#   framework: HIPAA Security Rule
#   controls:
#     - "164.312(a)(2)(iv)"
#   gap: GAP-02
#   severity: high
#   remediation: Enable table encryption with an enabled customer-managed KMS key defined in this plan.
package compliance.dynamodb_encryption

import rego.v1

# Verify table encryption and the referenced customer-managed key.
dynamodb_uses_customer_key(table) if {
	some encryption in table.change.after.server_side_encryption
	encryption.enabled == true

	key_arn := encryption.kms_key_arn
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

# Check every managed table remaining in the proposed configuration.
deny_dynamodb_encryption contains msg if {
	some table in input.resource_changes
	table.mode == "managed"
	table.type == "aws_dynamodb_table"
	table.change.after != null

	not dynamodb_uses_customer_key(table)

	msg := sprintf(
		"GAP-02 | HIPAA 164.312(a)(2)(iv): %s must enable encryption with an enabled customer-managed symmetric KMS key defined in this plan.",
		[table.address],
	)
}
