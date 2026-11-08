# HIPAA 164.308(a)(1)(ii)(D) / NIST SI-4: alert on a short list of
# control-breaking changes. The event names are the noise control.
# Both rules publish to the same SNS topic.

locals {
  control_change_events = [
    "StopLogging",
    "DeleteTrail",
    "PutBucketEncryption",
    "DeleteBucketEncryption",
  ]
  control_alerts_topic_name = "${local.name_prefix}-control-alerts-${local.suffix}"
}

# alias/aws/sns is not writable and does not allow events.amazonaws.com to
# call kms:GenerateDataKey or kms:Decrypt. EventBridge matches the rules and
# then fails the publish. A customer-managed key is the key EventBridge can use.
data "aws_iam_policy_document" "control_alerts_key" {
  statement {
    sid    = "EnableAccountAdministration"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  statement {
    sid    = "AllowEventBridgePublish"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey*",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid    = "AllowSnsDelivery"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["sns.amazonaws.com"]
    }
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey*",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values   = ["arn:aws:sns:${var.aws_region}:${data.aws_caller_identity.current.account_id}:${local.control_alerts_topic_name}"]
    }
  }
}

resource "aws_kms_key" "control_alerts" {
  description             = "Encrypts Acme Health control-change alerts."
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.control_alerts_key.json
}

resource "aws_kms_alias" "control_alerts" {
  name          = "alias/acme-health-control-alerts"
  target_key_id = aws_kms_key.control_alerts.key_id
}

resource "aws_sns_topic" "control_alerts" {
  name              = local.control_alerts_topic_name
  display_name      = "Acme Health control alerts"
  kms_master_key_id = aws_kms_key.control_alerts.arn
}

resource "aws_sns_topic_subscription" "control_alerts_email" {
  count = var.alert_email == "" ? 0 : 1

  topic_arn = aws_sns_topic.control_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_cloudwatch_event_rule" "control_changes" {
  name        = "${local.name_prefix}-control-changes-${local.suffix}"
  description = "Alert when CloudTrail logging or S3 bucket encryption is changed."

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail", "aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = local.control_change_events
      readOnly  = [false]
    }
  })
}

resource "aws_cloudwatch_event_rule" "config_noncompliant" {
  name        = "${local.name_prefix}-config-noncompliant-${local.suffix}"
  description = "Alert when the S3 encryption Config rule becomes noncompliant."

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      messageType    = ["ComplianceChangeNotification"]
      configRuleName = [aws_config_config_rule.s3_encryption.name]
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "control_changes" {
  rule      = aws_cloudwatch_event_rule.control_changes.name
  target_id = "control-alerts"
  arn       = aws_sns_topic.control_alerts.arn
}

resource "aws_cloudwatch_event_target" "config_noncompliant" {
  rule      = aws_cloudwatch_event_rule.config_noncompliant.name
  target_id = "control-alerts"
  arn       = aws_sns_topic.control_alerts.arn
}

data "aws_iam_policy_document" "control_alerts" {
  statement {
    sid     = "AllowEventBridgePublish"
    effect  = "Allow"
    actions = ["sns:Publish"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    resources = [aws_sns_topic.control_alerts.arn]
    condition {
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values = [
        aws_cloudwatch_event_rule.control_changes.arn,
        aws_cloudwatch_event_rule.config_noncompliant.arn,
      ]
    }
  }
}

resource "aws_sns_topic_policy" "control_alerts" {
  arn    = aws_sns_topic.control_alerts.arn
  policy = data.aws_iam_policy_document.control_alerts.json
}

output "control_alerts_topic_arn" {
  value       = aws_sns_topic.control_alerts.arn
  description = "SNS topic for CloudTrail control-change and Config noncompliance alerts."
}
