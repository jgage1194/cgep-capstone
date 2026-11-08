package compliance.detection_test

import data.compliance.detection
import rego.v1

required_events := [
	"StopLogging",
	"DeleteTrail",
	"PutBucketEncryption",
	"DeleteBucketEncryption",
]

api_pattern(event_names, read_only) := json.marshal({
	"source": ["aws.cloudtrail", "aws.s3"],
	"detail-type": ["AWS API Call via CloudTrail"],
	"detail": {
		"eventName": event_names,
		"readOnly": read_only,
	},
})

config_pattern(compliance_type) := json.marshal({
	"source": ["aws.config"],
	"detail-type": ["Config Rules Compliance Change"],
	"detail": {
		"messageType": ["ComplianceChangeNotification"],
		"configRuleName": ["s3-encryption"],
		"newEvaluationResult": {"complianceType": compliance_type},
	},
})

event_rule(address, name, pattern) := {
	"address": address,
	"mode": "managed",
	"type": "aws_cloudwatch_event_rule",
	"change": {"after": {"name": name, "event_pattern": pattern}},
}

event_target(address, rule_name, arn) := {
	"address": address,
	"mode": "managed",
	"type": "aws_cloudwatch_event_target",
	"change": {"after": {"rule": rule_name, "arn": arn}},
}

passing_changes := [
	event_rule(
		"aws_cloudwatch_event_rule.control_changes",
		"control-changes",
		api_pattern(required_events, [false]),
	),
	event_target(
		"aws_cloudwatch_event_target.control_changes",
		"control-changes",
		"arn:aws:sns:us-east-1:123456789012:control-alerts",
	),
	event_rule(
		"aws_cloudwatch_event_rule.config_noncompliant",
		"config-noncompliant",
		config_pattern(["NON_COMPLIANT"]),
	),
	event_target(
		"aws_cloudwatch_event_target.config_noncompliant",
		"config-noncompliant",
		"arn:aws:sns:us-east-1:123456789012:control-alerts",
	),
	{
		"address": "aws_config_config_rule.s3_encryption",
		"mode": "managed",
		"type": "aws_config_config_rule",
		"change": {"after": {
			"name": "s3-encryption",
			"source": [{
				"owner": "AWS",
				"source_identifier": "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED",
			}],
		}},
	},
	{
		"address": "aws_config_configuration_recorder_status.this",
		"mode": "managed",
		"type": "aws_config_configuration_recorder_status",
		"change": {"after": {"is_enabled": true}},
	},
]

plan(changes) := {"resource_changes": changes}

without(address) := [resource |
	some resource in passing_changes
	resource.address != address
]

messages_contain(changes, text) if {
	some msg in detection.deny_detection with input as plan(changes)
	contains(msg, text)
}

test_targeted_detection_passes if {
	count(detection.deny_detection) == 0 with input as plan(passing_changes)
}

test_missing_api_rule_fails if {
	messages_contain(without("aws_cloudwatch_event_rule.control_changes"), "StopLogging")
}

test_wildcard_event_name_fails if {
	changes := array.concat(
		without("aws_cloudwatch_event_rule.control_changes"),
		[event_rule(
			"aws_cloudwatch_event_rule.control_changes",
			"control-changes",
			api_pattern(["*"], [false]),
		)],
	)

	messages_contain(changes, "named read-write control changes")
}

test_read_only_events_fail if {
	changes := array.concat(
		without("aws_cloudwatch_event_rule.control_changes"),
		[event_rule(
			"aws_cloudwatch_event_rule.control_changes",
			"control-changes",
			api_pattern(required_events, [true]),
		)],
	)

	messages_contain(changes, "named read-write control changes")
}

test_api_rule_without_sns_fails if {
	messages_contain(without("aws_cloudwatch_event_target.control_changes"), "publish matching events to an SNS topic")
}

test_non_sns_target_fails if {
	changes := array.concat(
		without("aws_cloudwatch_event_target.control_changes"),
		[event_target(
			"aws_cloudwatch_event_target.control_changes",
			"control-changes",
			"arn:aws:lambda:us-east-1:123456789012:function:notify",
		)],
	)

	messages_contain(changes, "publish matching events to an SNS topic")
}

test_missing_config_rule_fails if {
	messages_contain(without("aws_config_config_rule.s3_encryption"), "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED")
}

test_disabled_recorder_fails if {
	changes := array.concat(
		without("aws_config_configuration_recorder_status.this"),
		[{
			"address": "aws_config_configuration_recorder_status.this",
			"mode": "managed",
			"type": "aws_config_configuration_recorder_status",
			"change": {"after": {"is_enabled": false}},
		}],
	)

	messages_contain(changes, "recorder must be enabled")
}

test_compliant_config_alert_fails if {
	changes := array.concat(
		without("aws_cloudwatch_event_rule.config_noncompliant"),
		[event_rule(
			"aws_cloudwatch_event_rule.config_noncompliant",
			"config-noncompliant",
			config_pattern(["COMPLIANT"]),
		)],
	)

	messages_contain(changes, "becomes NON_COMPLIANT")
}

test_config_alert_without_sns_fails if {
	messages_contain(without("aws_cloudwatch_event_target.config_noncompliant"), "publish Config findings to an SNS topic")
}

test_deleted_resources_do_not_satisfy_detection if {
	changes := [object.union(resource, {"change": {"after": null}}) |
		some resource in passing_changes
	]

	messages_contain(changes, "recorder must be enabled")
	messages_contain(changes, "StopLogging")
}
