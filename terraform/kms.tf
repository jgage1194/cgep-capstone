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