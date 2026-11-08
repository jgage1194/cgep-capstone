# METADATA
# title: Require targeted configuration-change detection
# description: Requires an enabled AWS Config recorder, an S3 encryption Config rule, and EventBridge alerts that publish only those findings to SNS.
# custom:
#   framework: HIPAA Security Rule
#   controls:
#     - "164.308(a)(1)(ii)(D)"
#     - "SI-4"
#   gap: GAP-06
#   severity: high
#   remediation: Keep the Config recorder enabled and alert only on the named control changes.
package compliance.detection

import rego.v1

# Keep this set identical to local.control_change_events in terraform/detection.tf.
required_event_names := {
	"StopLogging",
	"DeleteTrail",
	"PutBucketEncryption",
	"DeleteBucketEncryption",
}

# Event pattern fields arrive as one value or as an array.
detection_list(value) := value if is_array(value)

# Wrap a single value so set comparisons can iterate it.
detection_list(value) := [value] if not is_array(value)

# Compare event names and sources without depending on JSON array order.
detection_set(value) := {item | some item in detection_list(value)}

managed_of(type) := {resource |
	some resource in input.resource_changes
	resource.mode == "managed"
	resource.type == type
	resource.change.after != null
}

# Terraform stores event_pattern as a JSON string. An unreadable pattern does not match.
event_pattern(rule) := pattern if {
	is_string(rule.change.after.event_pattern)
	json.is_valid(rule.change.after.event_pattern)
	pattern := json.unmarshal(rule.change.after.event_pattern)
}

# CloudTrail API rules are the control-change alerts, separate from Config compliance alerts.
api_rules contains rule if {
	some rule in managed_of("aws_cloudwatch_event_rule")
	pattern := event_pattern(rule)
	pattern["detail-type"] == ["AWS API Call via CloudTrail"]
}

# Accept only the named read-write calls. A missing event list or readOnly true does not match.
targeted_api_rule(rule) if {
	pattern := event_pattern(rule)
	pattern["detail-type"] == ["AWS API Call via CloudTrail"]
	detection_set(pattern.source) == {"aws.cloudtrail", "aws.s3"}
	detection_set(pattern.detail.eventName) == required_event_names
	pattern.detail.readOnly == [false]
}

# Config compliance alerts use a different detail type from CloudTrail API calls.
config_alert_rules contains rule if {
	some rule in managed_of("aws_cloudwatch_event_rule")
	pattern := event_pattern(rule)
	pattern["detail-type"] == ["Config Rules Compliance Change"]
}

# The S3 encryption managed rule is the only Config rule this gate requires.
encryption_config_rules contains rule if {
	some rule in managed_of("aws_config_config_rule")
	some source in detection_list(rule.change.after.source)
	source.source_identifier == "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
}

# Page only when that encryption rule changes to NON_COMPLIANT.
targeted_config_alert(rule) if {
	pattern := event_pattern(rule)
	detection_set(pattern.source) == {"aws.config"}
	pattern["detail-type"] == ["Config Rules Compliance Change"]
	pattern.detail.messageType == ["ComplianceChangeNotification"]
	pattern.detail.newEvaluationResult.complianceType == ["NON_COMPLIANT"]

	some config_rule in encryption_config_rules
	pattern.detail.configRuleName == [config_rule.change.after.name]
}

# The alert route is an SNS topic. A Lambda or log target does not satisfy it.
has_sns_target(rule) if {
	some target in managed_of("aws_cloudwatch_event_target")
	target.change.after.rule == rule.change.after.name
	startswith(target.change.after.arn, "arn:aws:sns:")
}

# A recorder left in the plan with is_enabled false does not count.
config_recorder_enabled if {
	some status in managed_of("aws_config_configuration_recorder_status")
	status.change.after.is_enabled == true
}

# Fail when the plan has no rule limited to the named CloudTrail calls.
deny_detection contains msg if {
	count({rule | some rule in api_rules; targeted_api_rule(rule)}) == 0

	msg := "HIPAA 164.308(a)(1)(ii)(D) | NIST SI-4: the plan must include an EventBridge rule for read-write CloudTrail API calls named StopLogging, DeleteTrail, PutBucketEncryption, and DeleteBucketEncryption."
}

# A CloudTrail rule that watches every API call is still a failure, even if another rule is correct.
deny_detection contains msg if {
	some rule in api_rules
	not targeted_api_rule(rule)

	msg := sprintf(
		"HIPAA 164.308(a)(1)(ii)(D) | NIST SI-4: %s must alert only on the named read-write control changes, not on every CloudTrail API call.",
		[rule.address],
	)
}

# The matching CloudTrail rule must publish to SNS.
deny_detection contains msg if {
	some rule in api_rules
	targeted_api_rule(rule)
	not has_sns_target(rule)

	msg := sprintf(
		"HIPAA 164.308(a)(1)(ii)(D) | NIST SI-4: %s must publish matching events to an SNS topic.",
		[rule.address],
	)
}

# Fail when the S3 encryption Config rule is absent.
deny_detection contains msg if {
	count(encryption_config_rules) == 0

	msg := "HIPAA 164.308(a)(1)(ii)(D) | NIST SI-4: the plan must include the S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED AWS Config rule."
}

# Fail when no configuration recorder in the plan is enabled.
deny_detection contains msg if {
	not config_recorder_enabled

	msg := "HIPAA 164.308(a)(1)(ii)(D) | NIST SI-4: the AWS Config recorder must be enabled."
}

# Fail when nothing alerts on the encryption rule becoming NON_COMPLIANT.
deny_detection contains msg if {
	count({rule | some rule in config_alert_rules; targeted_config_alert(rule)}) == 0

	msg := "HIPAA 164.308(a)(1)(ii)(D) | NIST SI-4: the plan must alert when the S3 encryption Config rule changes to NON_COMPLIANT."
}

# A Config alert that fires on every result, including COMPLIANT, is too broad.
deny_detection contains msg if {
	some rule in config_alert_rules
	not targeted_config_alert(rule)

	msg := sprintf(
		"HIPAA 164.308(a)(1)(ii)(D) | NIST SI-4: %s must alert only when the S3 encryption Config rule becomes NON_COMPLIANT.",
		[rule.address],
	)
}

# The matching Config alert must publish to SNS.
deny_detection contains msg if {
	some rule in config_alert_rules
	targeted_config_alert(rule)
	not has_sns_target(rule)

	msg := sprintf(
		"HIPAA 164.308(a)(1)(ii)(D) | NIST SI-4: %s must publish Config findings to an SNS topic.",
		[rule.address],
	)
}
