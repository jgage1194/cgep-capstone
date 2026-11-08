# terraform/kms.tf

# GAP-01 (HIPAA 164.312(a)(2)(iv)): Creates a customer-managed key and alias for S3 uploads,
# with automatic rotation and a 7-day deletion waiting period.
resource "aws_kms_key" "uploads" {
  description             = "Encrypts Acme Health S3 intake attachments."
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "uploads" {
  name          = "alias/acme-health-uploads"
  target_key_id = aws_kms_key.uploads.key_id
}

# GAP-02 (HIPAA 164.312(a)(2)(iv)): Creates a customer-managed key and alias for DynamoDB submissions,
# with automatic rotation and a 7-day deletion waiting period.
resource "aws_kms_key" "submissions" {
  description             = "Encrypts Acme Health DynamoDB intake submissions."
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "submissions" {
  name          = "alias/acme-health-submissions"
  target_key_id = aws_kms_key.submissions.key_id
}

# GRC baseline: Creates a customer-managed key and alias for evidence,
# with automatic rotation and a 7-day deletion waiting period.
resource "aws_kms_key" "evidence" {
  description             = "Encrypts Acme Health deployment evidence."
  enable_key_rotation     = true
  deletion_window_in_days = 7
}

resource "aws_kms_alias" "evidence" {
  name          = "alias/acme-health-evidence"
  target_key_id = aws_kms_key.evidence.key_id
}

# CloudWatch Logs needs a customer-managed key. The AWS-managed logs key
# cannot be selected for these log groups.
data "aws_iam_policy_document" "logs_key" {
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
    sid    = "AllowCloudWatchLogs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${var.aws_region}.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:Describe*",
    ]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:*"]
    }
  }
}

resource "aws_kms_key" "logs" {
  description             = "Encrypts Acme Health CloudWatch logs."
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.logs_key.json
}

resource "aws_kms_alias" "logs" {
  name          = "alias/acme-health-logs"
  target_key_id = aws_kms_key.logs.key_id
}

# The execution role is named in the key policy, so Lambda can decrypt
# environment variables without a new inline identity policy.
data "aws_iam_policy_document" "lambda_env_key" {
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
    sid    = "AllowIntakeRoleDecrypt"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = [aws_iam_role.lambda.arn]
    }
    actions   = ["kms:Decrypt", "kms:DescribeKey"]
    resources = ["*"]
  }
}

resource "aws_kms_key" "lambda_env" {
  description             = "Encrypts Acme Health intake Lambda environment variables."
  enable_key_rotation     = true
  deletion_window_in_days = 7
  policy                  = data.aws_iam_policy_document.lambda_env_key.json
}

resource "aws_kms_alias" "lambda_env" {
  name          = "alias/acme-health-lambda-env"
  target_key_id = aws_kms_key.lambda_env.key_id
}
