# terraform/hardening.tf
# Gap-closing overrides on the starter's resources (HIPAA Security Rule)

# GAP-01 (HIPAA 164.312(a)(2)(iv)): Changes to SSE-KMS with Acme-owned CMK on the uploads S3 bucket
resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.uploads.arn
    }
    bucket_key_enabled = true
  }
}

# GAP-01 (HIPAA 164.312(a)(2)(iv)): Allows Lambda to use the uploads CMK through S3 for encrypted
# attachment uploads.
resource "aws_iam_role_policy" "lambda_uploads_kms" {
  name = "intake-uploads-kms"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.uploads.arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.us-east-1.amazonaws.com"
          }
        }
      }
    ]
  })
}

# GAP-02 (HIPAA 164.312(a)(2)(iv)): Allows Lambda to use the submissions CMK
# through DynamoDB so it can write intake records to the encrypted table.
resource "aws_iam_role_policy" "lambda_submissions_kms" {
  name = "intake-submissions-kms"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "kms:Decrypt"
        Resource = aws_kms_key.submissions.arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "dynamodb.us-east-1.amazonaws.com"
          }
        }
      }
    ]
  })
}

# GAP-03 (HIPAA 164.312(e)(1)): Denies non-TLS requests to the uploads bucket and its objects.
resource "aws_s3_bucket_policy" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.uploads.arn,
          "${aws_s3_bucket.uploads.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# GAP-04 (HIPAA 164.308(a)(7)): Enables uploads bucket versioning
# to support recovery from accidental overwrites and deletions.
resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  versioning_configuration {
    status = "Suspended"
  }
}

# GAP-05 (HIPAA 164.312(e)(1)): Associates the private subnets with
# a dedicated route table without an internet default route.
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  count = length(aws_subnet.private)

  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# GAP-05 (HIPAA 164.312(e)(1)): Provides private S3 connectivity
# through a gateway endpoint associated with the private route table.
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
}

# GAP-05 (HIPAA 164.312(e)(1)): Provides private DynamoDB connectivity
# through a gateway endpoint associated with the private route table.
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = aws_vpc.main.id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.private.id]
}

# GAP-05 (HIPAA 164.312(e)(1)): Restricts Lambda outbound traffic
# to HTTPS connections to regional S3 and DynamoDB endpoints.
resource "aws_security_group" "lambda" {
  name_prefix = "${local.name_prefix}-lambda-"
  description = "Lambda HTTPS access to S3 and DynamoDB"
  vpc_id      = aws_vpc.main.id

  egress {
    description = "HTTPS to S3 and DynamoDB"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    prefix_list_ids = [
      aws_vpc_endpoint.s3.prefix_list_id,
      aws_vpc_endpoint.dynamodb.prefix_list_id
    ]
  }
}

# GAP-05 (HIPAA 164.312(e)(1)): Allows Lambda to manage the network
# interfaces required for attachment to the private subnets.
resource "aws_iam_role_policy" "lambda_vpc" {
  name = "intake-vpc-access"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ec2:CreateNetworkInterface",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeSubnets",
          "ec2:DeleteNetworkInterface",
          "ec2:AssignPrivateIpAddresses",
          "ec2:UnassignPrivateIpAddresses"
        ]
        Resource = "*"
      }
    ]
  })
}

# GAP-06: Allows Lambda to publish trace segments and telemetry to X-Ray.
resource "aws_iam_role_policy" "lambda_xray" {
  name = "intake-xray-access"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "xray:PutTraceSegments",
          "xray:PutTelemetryRecords"
        ]
        Resource = "*"
      }
    ]
  })
}

# GAP-06: Creates an encrypted dead-letter queue that retains
# failed asynchronous intake events for 14 days.
resource "aws_sqs_queue" "intake_dlq" {
  name                      = "${local.name_prefix}-dlq-${local.suffix}"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

# GAP-06: Allows Lambda to deliver failed asynchronous events
# to the intake dead-letter queue.
resource "aws_iam_role_policy" "lambda_dlq" {
  name = "intake-dlq-access"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "sqs:SendMessage"
        Resource = aws_sqs_queue.intake_dlq.arn
      }
    ]
  })
}

# GAP-08 (HIPAA 164.312(b)): Creates an API access log group
# with a 30-day retention period for this sandbox.
resource "aws_cloudwatch_log_group" "api_access" {
  name              = "/aws/apigateway/${local.name_prefix}-${local.suffix}"
  retention_in_days = 30
}

# GRC baseline: Shared Terraform state for local and GitHub Actions runs.
resource "aws_s3_bucket" "tfstate" {
  bucket = "${local.name_prefix}-tfstate-${local.suffix}"

  tags = {
    DataClass = "infrastructure"
  }
}

# Preserve previous state versions for recovery.
resource "aws_s3_bucket_versioning" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_public_access_block" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Reuse the existing evidence encryption key for this capstone.
resource "aws_s3_bucket_server_side_encryption_configuration" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.evidence.arn
    }

    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "tfstate" {
  bucket = aws_s3_bucket.tfstate.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.tfstate.arn,
        "${aws_s3_bucket.tfstate.arn}/*"
      ]
      Condition = {
        Bool = {
          "aws:SecureTransport" = "false"
        }
      }
    }]
  })
}

# Prevent public access to the patient uploads bucket.
resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}