# METADATA
# title: Require HTTPS for all managed S3 buckets
# description: Rejects buckets without a policy denying insecure transport.
# custom:
#   framework: HIPAA Security Rule
#   controls:
#     - "164.312(e)(1)"
#   gap: GAP-03
#   severity: high
#   remediation: Deny non-TLS S3 actions on the bucket and its objects.
package compliance.s3_secure_transport

import rego.v1

# IAM permits some fields to be either a single value or an array.
s3_tls_list(value) := value if is_array(value)

s3_tls_list(value) := [value] if not is_array(value)

# Accept both common representations of all principals.
s3_tls_all_principals(statement) if {
	statement.Principal == "*"
}

s3_tls_all_principals(statement) if {
	"*" in s3_tls_list(statement.Principal.AWS)
}

# Find a bucket policy with a complete insecure-transport deny.
s3_bucket_requires_tls(bucket) if {
	bucket_name := bucket.change.after.bucket
	is_string(bucket_name)
	bucket_name != ""

	bucket_arn := bucket.change.after.arn
	is_string(bucket_arn)
	bucket_arn != ""

	some policy in input.resource_changes
	policy.mode == "managed"
	policy.type == "aws_s3_bucket_policy"
	policy.change.after.bucket == bucket_name

	document := json.unmarshal(policy.change.after.policy)
	some statement in s3_tls_list(document.Statement)

	statement.Effect == "Deny"
	s3_tls_all_principals(statement)

	actions := s3_tls_list(statement.Action)
	some action in actions
	action in {"s3:*", "*"}

	resources := s3_tls_list(statement.Resource)
	bucket_arn in resources
	sprintf("%s/*", [bucket_arn]) in resources

	statement.Condition.Bool["aws:SecureTransport"] in {"false", false}
}

# Evaluate every managed bucket remaining in the proposed configuration.
deny_s3_secure_transport contains msg if {
	some bucket in input.resource_changes
	bucket.mode == "managed"
	bucket.type == "aws_s3_bucket"
	bucket.change.after != null

	not s3_bucket_requires_tls(bucket)

	msg := sprintf(
		"GAP-03 | HIPAA 164.312(e)(1): %s must deny non-TLS s3:* access for all principals on both the bucket and its objects.",
		[bucket.address],
	)
}
