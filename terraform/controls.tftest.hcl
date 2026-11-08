# Plan-level checks for the controls the capstone deploys.
# Mocked AWS data sources keep the test from calling a live account.

mock_provider "aws" {
  override_data {
    target = data.aws_caller_identity.current
    values = {
      account_id = "123456789012"
      arn        = "arn:aws:iam::123456789012:root"
      id         = "123456789012"
      user_id    = "AIDACKCEVSQ6C2EXAMPLE"
    }
  }

  override_data {
    target = data.aws_availability_zones.available
    values = {
      names    = ["us-east-1a", "us-east-1b", "us-east-1c"]
      zone_ids = ["use1-az1", "use1-az2", "use1-az3"]
      state    = "available"
    }
  }

  override_data {
    target = data.aws_iam_openid_connect_provider.github[0]
    values = {
      arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      url = "https://token.actions.githubusercontent.com"
      id  = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
    }
  }

  # The AWS provider builds these documents. The mock must still return JSON.
  override_data {
    target = data.aws_iam_policy_document.logs_key
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.lambda_env_key
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.control_alerts_key
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.control_alerts
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.config_bucket
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.trail
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
  override_data {
    target = data.aws_iam_policy_document.evidence_schedule_logs
    values = { json = "{\"Version\":\"2012-10-17\",\"Statement\":[]}" }
  }
}

override_resource {
  target          = aws_kms_key.logs
  override_during = plan
  values = {
    arn = "arn:aws:kms:us-east-1:123456789012:key/logs"
  }
}

override_resource {
  target          = aws_kms_key.lambda_env
  override_during = plan
  values = {
    arn = "arn:aws:kms:us-east-1:123456789012:key/lambda-env"
  }
}

variables {
  github_org  = "jgage1194"
  github_repo = "cgep-capstone"
  aws_region  = "us-east-1"
}

run "control_settings" {
  command = plan

  assert {
    condition = alltrue([
      for subnet in aws_subnet.public : subnet.map_public_ip_on_launch == false
    ])
    error_message = "Public subnets must not assign a public IP on launch."
  }

  assert {
    condition     = aws_lambda_function.intake.reserved_concurrent_executions == 5
    error_message = "Intake Lambda must reserve five concurrent executions."
  }

  assert {
    condition     = aws_lambda_function.intake.kms_key_arn == aws_kms_key.lambda_env.arn
    error_message = "Intake environment variables must use the customer-managed Lambda key."
  }

  assert {
    condition     = aws_cloudwatch_log_group.api_access.kms_key_id == aws_kms_key.logs.arn
    error_message = "API access logs must use the customer-managed logs key."
  }

  assert {
    condition     = aws_cloudwatch_log_group.lambda.kms_key_id == aws_kms_key.logs.arn
    error_message = "Lambda logs must use the customer-managed logs key."
  }

  assert {
    condition     = aws_cloudwatch_event_rule.evidence_collection.schedule_expression == "rate(1 day)"
    error_message = "EventBridge must collect the daily evidence marker."
  }

  assert {
    condition     = aws_s3_bucket.vault.object_lock_enabled == true
    error_message = "The evidence vault must have Object Lock enabled."
  }
}
