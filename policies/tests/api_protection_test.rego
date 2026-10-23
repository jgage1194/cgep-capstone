package compliance.api_protection_test

import data.compliance.api_protection
import rego.v1

log_arn := "arn:aws:logs:us-east-1:123456789012:log-group:/aws/apigateway/intake"

log_group := {
	"address": "aws_cloudwatch_log_group.api_access",
	"mode": "managed",
	"type": "aws_cloudwatch_log_group",
	"change": {"after": {"arn": log_arn}},
}

logging := {
	"destination_arn": log_arn,
	"format": json.marshal({
		"requestId": "$context.requestId",
		"status": "$context.status",
	}),
}

settings := {
	"access_log_settings": [logging],
	"default_route_settings": [{
		"throttling_rate_limit": 5,
		"throttling_burst_limit": 10,
	}],
}

stage_resource(after) := {
	"address": "aws_apigatewayv2_stage.default",
	"mode": "managed",
	"type": "aws_apigatewayv2_stage",
	"change": {"after": after},
}

api_plan(after) := {
	"resource_changes": [stage_resource(after), log_group],
}

# Passing fixtures must satisfy both blocking checks.
no_api_denials(plan) if {
	count(api_protection.deny_api_access_logging) == 0 with input as plan
	count(api_protection.deny_api_throttling) == 0 with input as plan
}

test_baseline_passes_with_waf_warning if {
	plan := api_plan(settings)
	no_api_denials(plan)

	warnings := api_protection.warn_api_waf_exception with input as plan
	count(warnings) == 1

	some msg in warnings
	contains(msg, "GAP-08")
	contains(msg, "OPEN EXCEPTION")
}

test_missing_logging_fails if {
	plan := api_plan(object.remove(settings, {"access_log_settings"}))

	failures := api_protection.deny_api_access_logging with input as plan
	count(failures) == 1

	some msg in failures
	contains(msg, "164.312(b)")
	contains(msg, "aws_apigatewayv2_stage.default")
}

test_invalid_logging_settings_fail if {
	every value in [[], null, [{}]] {
		plan := api_plan(object.union(settings, {
			"access_log_settings": value,
		}))

		failures := api_protection.deny_api_access_logging with input as plan
		count(failures) == 1
	}
}

test_invalid_destinations_fail if {
	every destination in [
		null,
		"",
		"arn:aws:logs:us-east-1:123456789012:log-group:other",
	] {
		value := object.union(logging, {
			"destination_arn": destination,
		})

		plan := api_plan(object.union(settings, {
			"access_log_settings": [value],
		}))

		failures := api_protection.deny_api_access_logging with input as plan
		count(failures) == 1
	}
}

test_missing_log_group_fails if {
	plan := {"resource_changes": [stage_resource(settings)]}

	failures := api_protection.deny_api_access_logging with input as plan
	count(failures) == 1
}

test_invalid_log_formats_fail if {
	every format in [null, "", "not-json", "[]", "{}"] {
		value := object.union(logging, {"format": format})

		plan := api_plan(object.union(settings, {
			"access_log_settings": [value],
		}))

		failures := api_protection.deny_api_access_logging with input as plan
		count(failures) == 1
	}
}

test_missing_required_log_values_fail if {
	every fields in [
		{"requestId": "$context.requestId"},
		{"status": "$context.status"},
		{"requestId": "literal", "status": "$context.status"},
	] {
		value := object.union(logging, {
			"format": json.marshal(fields),
		})

		plan := api_plan(object.union(settings, {
			"access_log_settings": [value],
		}))

		failures := api_protection.deny_api_access_logging with input as plan
		count(failures) == 1
	}
}

# The context values matter; JSON field names are a design choice.
test_alternative_log_field_names_pass if {
	value := object.union(logging, {
		"format": json.marshal({
			"id": "$context.requestId",
			"responseStatus": "$context.status",
		}),
	})

	plan := api_plan(object.union(settings, {
		"access_log_settings": [value],
	}))

	no_api_denials(plan)
}

test_invalid_throttling_fails if {
	every value in [
		[],
		null,
		[{}],
		[{"throttling_rate_limit": 0, "throttling_burst_limit": 10}],
		[{"throttling_rate_limit": 5, "throttling_burst_limit": 0}],
		[{"throttling_rate_limit": -1, "throttling_burst_limit": 10}],
		[{"throttling_rate_limit": "5", "throttling_burst_limit": 10}],
		[{"throttling_rate_limit": 5}],
		[{"throttling_burst_limit": 10}],
	] {
		plan := api_plan(object.union(settings, {
			"default_route_settings": value,
		}))

		failures := api_protection.deny_api_throttling with input as plan
		count(failures) == 1
	}
}

test_missing_throttling_fails if {
	plan := api_plan(object.remove(settings, {"default_route_settings"}))

	failures := api_protection.deny_api_throttling with input as plan
	count(failures) == 1
}

# Creating an unrelated WAF must not close the recorded exception.
test_unrelated_waf_keeps_warning if {
	original := api_plan(settings)

	waf := {
		"address": "aws_wafv2_web_acl.unrelated",
		"mode": "managed",
		"type": "aws_wafv2_web_acl",
		"change": {"after": {"name": "unrelated"}},
	}

	plan := {
		"resource_changes": array.concat(original.resource_changes, [waf]),
	}

	no_api_denials(plan)
	count(api_protection.warn_api_waf_exception) == 1 with input as plan
}

test_second_unprotected_stage_fails if {
	original := api_plan(settings)

	second := object.union(stage_resource({}), {
		"address": "aws_apigatewayv2_stage.second",
	})

	plan := {
		"resource_changes": array.concat(original.resource_changes, [second]),
	}

	count(api_protection.deny_api_access_logging) == 1 with input as plan
	count(api_protection.deny_api_throttling) == 1 with input as plan
	count(api_protection.warn_api_waf_exception) == 2 with input as plan
}

test_module_stage_passes if {
	stage := object.union(stage_resource(settings), {
		"address": "module.api.aws_apigatewayv2_stage.default",
	})

	plan := {"resource_changes": [stage, log_group]}

	no_api_denials(plan)
	count(api_protection.warn_api_waf_exception) == 1 with input as plan
}

test_deleted_stage_passes if {
	stage := object.union(stage_resource({}), {
		"change": {
			"actions": ["delete"],
			"after": null,
		},
	})

	plan := {"resource_changes": [stage]}

	no_api_denials(plan)
	count(api_protection.warn_api_waf_exception) == 0 with input as plan
}

test_stage_data_source_passes if {
	stage := object.union(stage_resource({}), {"mode": "data"})
	plan := {"resource_changes": [stage]}

	no_api_denials(plan)
	count(api_protection.warn_api_waf_exception) == 0 with input as plan
}

test_no_stages_passes if {
	plan := {"resource_changes": []}

	no_api_denials(plan)
	count(api_protection.warn_api_waf_exception) == 0 with input as plan
}
