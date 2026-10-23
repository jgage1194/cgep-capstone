package compliance.lambda_resilience_test

import data.compliance.lambda_resilience
import rego.v1

settings := {
	"tracing_config": [{"mode": "Active"}],
	"dead_letter_config": [{
		"target_arn": "arn:aws:sqs:us-east-1:123456789012:intake-dlq",
	}],
	"reserved_concurrent_executions": 5,
}

lambda_resource(after) := {
	"address": "aws_lambda_function.example",
	"mode": "managed",
	"type": "aws_lambda_function",
	"change": {"after": after},
}

resilience_plan(after) := {
	"resource_changes": [lambda_resource(after)],
}

test_complete_configuration_passes if {
	plan := resilience_plan(settings)

	count(lambda_resilience.deny_lambda_tracing) == 0 with input as plan
	count(lambda_resilience.deny_lambda_dlq) == 0 with input as plan
	count(lambda_resilience.warn_lambda_concurrency) == 0 with input as plan
}

# Each invalid tracing setting must trigger the blocking rule.
test_invalid_tracing_fails if {
	every tracing in [[], null, [{}], [{"mode": "PassThrough"}]] {
		after := object.union(settings, {"tracing_config": tracing})
		plan := resilience_plan(after)

		failures := lambda_resilience.deny_lambda_tracing with input as plan
		count(failures) == 1

		some msg in failures
		contains(msg, "GAP-06")
		contains(msg, "SOC 2 CC7.2")
		contains(msg, "CMMC SI.L2-3.14.6")
	}
}

test_missing_tracing_field_fails if {
	plan := resilience_plan(object.remove(settings, {"tracing_config"}))

	failures := lambda_resilience.deny_lambda_tracing with input as plan
	count(failures) == 1
}

test_invalid_dlq_fails if {
	every dlq in [
		[],
		null,
		[{}],
		[{"target_arn": null}],
		[{"target_arn": ""}],
		[{"target_arn": "not-an-arn"}],
		[{"target_arn": "arn:aws:sns:us-east-1:123456789012:topic"}],
	] {
		after := object.union(settings, {"dead_letter_config": dlq})
		plan := resilience_plan(after)

		failures := lambda_resilience.deny_lambda_dlq with input as plan
		count(failures) == 1
	}
}

test_missing_dlq_field_fails if {
	plan := resilience_plan(object.remove(settings, {"dead_letter_config"}))

	failures := lambda_resilience.deny_lambda_dlq with input as plan
	count(failures) == 1
}

# Missing positive concurrency must warn without producing denials.
test_unreserved_concurrency_warns_only if {
	every value in [-1, null] {
		after := object.union(settings, {
			"reserved_concurrent_executions": value,
		})
		plan := resilience_plan(after)

		warnings := lambda_resilience.warn_lambda_concurrency with input as plan
		count(warnings) == 1

		some msg in warnings
		contains(msg, "OPEN EXCEPTION")

		count(lambda_resilience.deny_lambda_tracing) == 0 with input as plan
		count(lambda_resilience.deny_lambda_dlq) == 0 with input as plan
	}
}

test_missing_concurrency_warns_only if {
	plan := resilience_plan(object.remove(settings, {"reserved_concurrent_executions"}))

	count(lambda_resilience.warn_lambda_concurrency) == 1 with input as plan
	count(lambda_resilience.deny_lambda_tracing) == 0 with input as plan
	count(lambda_resilience.deny_lambda_dlq) == 0 with input as plan
}

test_positive_concurrency_clears_warning if {
	every value in [1, 5, 10] {
		plan := resilience_plan(object.union(settings, {
			"reserved_concurrent_executions": value,
		}))

		count(lambda_resilience.warn_lambda_concurrency) == 0 with input as plan
	}
}

test_all_settings_missing_reports_each_issue if {
	plan := resilience_plan({})

	count(lambda_resilience.deny_lambda_tracing) == 1 with input as plan
	count(lambda_resilience.deny_lambda_dlq) == 1 with input as plan
	count(lambda_resilience.warn_lambda_concurrency) == 1 with input as plan
}

test_module_lambda_passes if {
	function := object.union(lambda_resource(settings), {
		"address": "module.api.aws_lambda_function.handler",
	})
	plan := {"resource_changes": [function]}

	count(lambda_resilience.deny_lambda_tracing) == 0 with input as plan
	count(lambda_resilience.deny_lambda_dlq) == 0 with input as plan
	count(lambda_resilience.warn_lambda_concurrency) == 0 with input as plan
}

test_second_unprotected_lambda_fails if {
	second := object.union(lambda_resource({}), {
		"address": "aws_lambda_function.second",
	})
	plan := {
		"resource_changes": [lambda_resource(settings), second],
	}

	count(lambda_resilience.deny_lambda_tracing) == 1 with input as plan
	count(lambda_resilience.deny_lambda_dlq) == 1 with input as plan
	count(lambda_resilience.warn_lambda_concurrency) == 1 with input as plan
}

test_deleted_lambda_passes if {
	function := object.union(lambda_resource({}), {
		"change": {
			"actions": ["delete"],
			"after": null,
		},
	})
	plan := {"resource_changes": [function]}

	count(lambda_resilience.deny_lambda_tracing) == 0 with input as plan
	count(lambda_resilience.deny_lambda_dlq) == 0 with input as plan
	count(lambda_resilience.warn_lambda_concurrency) == 0 with input as plan
}

test_lambda_data_source_passes if {
	function := object.union(lambda_resource({}), {"mode": "data"})
	plan := {"resource_changes": [function]}

	count(lambda_resilience.deny_lambda_tracing) == 0 with input as plan
	count(lambda_resilience.deny_lambda_dlq) == 0 with input as plan
	count(lambda_resilience.warn_lambda_concurrency) == 0 with input as plan
}

test_no_lambdas_passes if {
	plan := {"resource_changes": []}

	count(lambda_resilience.deny_lambda_tracing) == 0 with input as plan
	count(lambda_resilience.deny_lambda_dlq) == 0 with input as plan
	count(lambda_resilience.warn_lambda_concurrency) == 0 with input as plan
}
