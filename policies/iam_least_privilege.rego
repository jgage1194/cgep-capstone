# METADATA
# title: Reject broad permissions in inline IAM role policies
# description: Requires explicit actions and restricts unrestricted resource grants to documented Lambda operational permissions.
# custom:
#   framework: HIPAA Security Rule
#   controls:
#     - "164.312(a)(1)"
#   gap: GAP-07
#   severity: high
#   remediation: Use explicit actions and scoped resources; retain only documented operational wildcard-resource allowances.
package compliance.iam_least_privilege

import rego.v1

# IAM accepts either one value or an array.
# Normalize both forms so the checks below can iterate consistently.
iam_list(value) := value if is_array(value)

iam_list(value) := [value] if not is_array(value)

# Find all managed inline role policies remaining in the plan.
inline_role_policies contains policy if {
	some policy in input.resource_changes
	policy.mode == "managed"
	policy.type == "aws_iam_role_policy"
	policy.change.after != null
}

# These exact operational actions may use Resource = "*" in this project.
# This is not a blanket exemption for EC2 or X-Ray permissions.
wildcard_resource_actions := {
	"ec2:createnetworkinterface",
	"ec2:describenetworkinterfaces",
	"ec2:describesubnets",
	"ec2:deletenetworkinterface",
	"ec2:assignprivateipaddresses",
	"ec2:unassignprivateipaddresses",
	"xray:puttracesegments",
	"xray:puttelemetryrecords",
}

# Deny statements do not grant permissions.
# Wildcards in a Deny therefore do not trigger our permission checks.
iam_statement_supported(statement) if {
	statement.Effect == "Deny"
}

# Allow statements must explicitly list actions and resources.
# NotAction and NotResource are intentionally unsupported by this baseline.
iam_statement_supported(statement) if {
	statement.Effect == "Allow"

	object.get(statement, "NotAction", null) == null
	object.get(statement, "NotResource", null) == null

	actions := iam_list(statement.Action)
	resources := iam_list(statement.Resource)

	count(actions) > 0
	count(resources) > 0

	every action in actions {
		is_string(action)
		action != ""
	}

	every resource in resources {
		is_string(resource)
		resource != ""
	}
}

# Decode the JSON string stored in Terraform's policy field.
# Missing, unresolved, or unsupported documents fail this check.
iam_document_supported(policy) if {
	document := json.unmarshal(policy.change.after.policy)
	is_object(document)

	statements := iam_list(document.Statement)
	count(statements) > 0

	every statement in statements {
		iam_statement_supported(statement)
	}
}

# BLOCK: prevent unreadable documents from silently bypassing inspection.
deny_iam_document contains msg if {
	some policy in inline_role_policies
	not iam_document_supported(policy)

	msg := sprintf(
		"GAP-07 | HIPAA 164.312(a)(1): %s must contain readable policy JSON with explicit Allow actions and resources.",
		[policy.address],
	)
}

# BLOCK: require specific action names rather than wildcard patterns.
deny_iam_wildcard_actions contains msg if {
	some policy in inline_role_policies
	document := json.unmarshal(policy.change.after.policy)

	some statement in iam_list(document.Statement)
	statement.Effect == "Allow"

	some action in iam_list(statement.Action)
	regex.match("[*?]", action)

	msg := sprintf(
		"GAP-07 | HIPAA 164.312(a)(1): %s grants wildcard action %s; enumerate the required actions.",
		[policy.address, action],
	)
}

# BLOCK: every action granted on all resources needs an explicit allowance.
deny_iam_unrestricted_resources contains msg if {
	some policy in inline_role_policies
	document := json.unmarshal(policy.change.after.policy)

	some statement in iam_list(document.Statement)
	statement.Effect == "Allow"
	"*" in iam_list(statement.Resource)

	some action in iam_list(statement.Action)
	not lower(action) in wildcard_resource_actions

	msg := sprintf(
		"GAP-07 | HIPAA 164.312(a)(1): %s grants %s on all resources without a documented operational allowance.",
		[policy.address, action],
	)
}
