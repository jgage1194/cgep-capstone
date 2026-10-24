# METADATA
# title: Require Lambda tracing and a dead-letter queue
# description: Blocks missing tracing or DLQ configuration and warns about missing positive reserved concurrency.
# custom:
#   framework: HIPAA Security Rule
#   frameworks:
#     - "HIPAA Security Rule"
#     - "SOC 2"
#     - "CMMC Level 2"
#   controls:
#     - "164.308(a)(1)(ii)(D)"
#     - "SOC 2 CC7.2"
#     - "CMMC SI.L2-3.14.6"
#   mapping_note: Supporting safeguards; these checks alone do not satisfy the mapped controls.
#   gap: GAP-06
#   severity: medium
#   remediation: Enable active tracing, configure a DLQ, and set positive reserved concurrency when account quota permits.
package compliance.lambda_resilience

import rego.v1

# Find every managed Lambda remaining in the plan.
managed_lambdas contains function if {
	some function in input.resource_changes
	function.mode == "managed"
	function.type == "aws_lambda_function"
	function.change.after != null
}

# Pass when tracing is explicitly Active.
has_active_tracing(function) if {
	some tracing in function.change.after.tracing_config
	tracing.mode == "Active"
}

# Pass when an SQS dead-letter target is configured.
has_dlq(function) if {
	some dlq in function.change.after.dead_letter_config
	is_string(dlq.target_arn)
	startswith(dlq.target_arn, "arn:")
	contains(dlq.target_arn, ":sqs:")
}

# Pass when reserved concurrency is a positive number.
has_positive_reserved_concurrency(function) if {
	value := function.change.after.reserved_concurrent_executions
	is_number(value)
	value > 0
}

# BLOCK: tracing is part of the required deployed baseline.
deny_lambda_tracing contains msg if {
	some function in managed_lambdas
	not has_active_tracing(function)

	msg := sprintf(
		"GAP-06 | HIPAA 164.308(a)(1)(ii)(D) (supporting safeguard): %s must enable Active X-Ray tracing.",
		[function.address],
	)
}

# BLOCK: require an SQS dead-letter target.
deny_lambda_dlq contains msg if {
	some function in managed_lambdas
	not has_dlq(function)

	msg := sprintf(
		"GAP-06 | HIPAA 164.308(a)(1)(ii)(D) (supporting safeguard): %s must configure an SQS dead-letter queue ARN.",
		[function.address],
	)
}

# WARN: documented exception while the quota increase is pending.
warn_lambda_concurrency contains msg if {
	some function in managed_lambdas
	not has_positive_reserved_concurrency(function)

	msg := sprintf(
		"GAP-06 | HIPAA 164.308(a)(1)(ii)(D) (supporting safeguard) | OPEN EXCEPTION: %s has no positive reserved concurrency. Account quota increase pending; review this exception when approved.",
		[function.address],
	)
}
