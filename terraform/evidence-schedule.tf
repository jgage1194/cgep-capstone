# Daily evidence marker collected by EventBridge, outside a GitHub
# workflow run. Signed bundles still come from the workflow. This log
# group only records that the schedule fired.
#
# EventBridge can write only to log groups under /aws/events/.

resource "aws_cloudwatch_log_group" "evidence_schedule" {
  name              = "/aws/events/${local.name_prefix}-evidence-${local.suffix}"
  retention_in_days = 30
  kms_key_id        = aws_kms_key.logs.arn
}

resource "aws_cloudwatch_event_rule" "evidence_collection" {
  name                = "${local.name_prefix}-evidence-schedule-${local.suffix}"
  description         = "Daily evidence marker collected outside a GitHub workflow run."
  schedule_expression = "rate(1 day)"
}

data "aws_iam_policy_document" "evidence_schedule_logs" {
  statement {
    sid    = "AllowEventBridgeWrite"
    effect = "Allow"
    principals {
      type = "Service"
      identifiers = [
        "events.amazonaws.com",
        "delivery.logs.amazonaws.com",
      ]
    }
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.evidence_schedule.arn}:*"]
  }
}

resource "aws_cloudwatch_log_resource_policy" "evidence_schedule" {
  policy_name     = "${local.name_prefix}-evidence-schedule"
  policy_document = data.aws_iam_policy_document.evidence_schedule_logs.json
}

resource "aws_cloudwatch_event_target" "evidence_collection" {
  rule      = aws_cloudwatch_event_rule.evidence_collection.name
  target_id = "evidence-log"
  arn       = aws_cloudwatch_log_group.evidence_schedule.arn

  input = jsonencode({
    collected_by = "eventbridge"
    purpose      = "daily-evidence-marker"
  })
}
