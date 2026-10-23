# METADATA
# title: Require API access logging and throttling
# description: Blocks missing API Gateway v2 logging or throttling and reports the documented WAF exception.
# custom:
#   framework: HIPAA Security Rule
#   controls:
#     - "164.312(b)"
#   mapping_note: Access logging supports audit controls; throttling and WAF are additional project safeguards.
#   gap: GAP-08
#   severity: high
#   remediation: Configure structured access logs and positive throttling targets; track WAF protection as an open exception.
package compliance.api_protection

import rego.v1

# This project's HTTP API uses API Gateway v2 stages.
# Collect all managed stages that will remain after applying the plan.
managed_api_stages contains stage if {
	some stage in input.resource_changes
	stage.mode == "managed"
	stage.type == "aws_apigatewayv2_stage"
	stage.change.after != null
}

# Require a known CloudWatch log group managed in the same plan.
# The JSON log format must include request ID and response status.
has_api_access_logging(stage) if {
	some logging in stage.change.after.access_log_settings

	destination := logging.destination_arn
	is_string(destination)
	destination != ""

	some group in input.resource_changes
	group.mode == "managed"
	group.type == "aws_cloudwatch_log_group"
	group.change.after.arn == destination

	format := json.unmarshal(logging.format)
	is_object(format)

	# Field names may differ, but these two context values must be logged.
	some request_field, status_field
	format[request_field] == "$context.requestId"
	format[status_field] == "$context.status"
}

# Require positive sustained-rate and burst targets.
has_api_throttling(stage) if {
	some settings in stage.change.after.default_route_settings

	is_number(settings.throttling_rate_limit)
	settings.throttling_rate_limit > 0

	is_number(settings.throttling_burst_limit)
	settings.throttling_burst_limit > 0
}

# BLOCK when the logging check cannot establish compliance.
deny_api_access_logging contains msg if {
	some stage in managed_api_stages
	not has_api_access_logging(stage)

	msg := sprintf(
		"GAP-08 | HIPAA 164.312(b): %s must send structured access logs containing request ID and status to a CloudWatch log group defined in this plan.",
		[stage.address],
	)
}

# BLOCK when either default throttling target is missing or nonpositive.
deny_api_throttling contains msg if {
	some stage in managed_api_stages
	not has_api_throttling(stage)

	msg := sprintf(
		"GAP-08 | GRC baseline: %s must configure positive default throttling rate and burst targets.",
		[stage.address],
	)
}

# WARN about the recorded WAF exception.
# This does not automatically detect whether a WAF is attached.
# Update this rule after verifying protection and closing the exception.
warn_api_waf_exception contains msg if {
	some stage in managed_api_stages

    msg := sprintf(
	    "GAP-08 | HIPAA 164.312(b) (supporting safeguard) | OPEN EXCEPTION: WAF protection and associated request logging for %s are deferred. Verify traffic coverage, logging, and origin-bypass prevention before closing this exception.",
	    [stage.address],
    )
}