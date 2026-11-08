variable "github_org" {
  type        = string
  description = "GitHub repository owner permitted to run the gate."
}
variable "github_repo" {
  type        = string
  description = "GitHub repository name permitted to run the gate."
}

variable "create_github_oidc_provider" {
  type        = bool
  default     = false
  description = "Create the account-wide GitHub OIDC provider only when none exists."
}

# Preserve existing deployments by reusing the provider unless creation is requested.
data "aws_iam_openid_connect_provider" "github" {
  count = var.create_github_oidc_provider ? 0 : 1
  url   = "https://token.actions.githubusercontent.com"
}

resource "aws_iam_openid_connect_provider" "github" {
  count          = var.create_github_oidc_provider ? 1 : 0
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

locals {
  github_oidc_arn = var.create_github_oidc_provider ? aws_iam_openid_connect_provider.github[0].arn : data.aws_iam_openid_connect_provider.github[0].arn
}

resource "aws_iam_role" "grc_gate" {
  name = "cgep-capstone-grc-gate"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = local.github_oidc_arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            "repo:${var.github_org}/${var.github_repo}:*",     # repos created before Jul 15 2026
            "repo:${var.github_org}@*/${var.github_repo}@*:*", # repos created after: GitHub adds owner + repo IDs
          ]
        }
      }
    }]
  })
}

# GRC baseline: Lets the PR gate read encrypted state and manage
# the temporary lock without granting permission to overwrite state.
resource "aws_iam_role_policy" "grc_gate_state" {
  name = "capstone-state-access"
  role = aws_iam_role.grc_gate.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ManageStateLock"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "${aws_s3_bucket.tfstate.arn}/capstone/terraform.tfstate.tflock"
      },
      {
        Sid    = "UseStateEncryptionKey"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.evidence.arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${var.aws_region}.amazonaws.com"
          }
        }
      }
    ]
  })
}

# Allow the GRC pipeline to upload evidence under the runs/ prefix.
resource "aws_iam_role_policy" "grc_gate_evidence" {
  name = "capstone-evidence-upload"
  role = aws_iam_role.grc_gate.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "UploadRunEvidence"
      Effect   = "Allow"
      Action   = "s3:PutObject"
      Resource = "${aws_s3_bucket.vault.arn}/runs/*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.grc_gate.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

output "role_arn" { value = aws_iam_role.grc_gate.arn }

# Deployment role: GitHub may assume it only from main.
resource "aws_iam_role" "grc_deploy" {
  name = "cgep-capstone-deploy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = local.github_oidc_arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        }
        StringLike = {
          "token.actions.githubusercontent.com:sub" = [
            "repo:${var.github_org}/${var.github_repo}:ref:refs/heads/main",
            "repo:${var.github_org}@*/${var.github_repo}@*:ref:refs/heads/main"
          ]
        }
      }
    }]
  })
}

# Terraform needs to read existing infrastructure when planning.
resource "aws_iam_role_policy_attachment" "deploy_readonly" {
  role       = aws_iam_role.grc_deploy.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Non-IAM changes for this stack: VPC, data stores, KMS, logging, Config,
# EventBridge, and the evidence bucket. IAM writes stay in deploy_iam.
resource "aws_iam_role_policy_attachment" "deploy_power_user" {
  role       = aws_iam_role.grc_deploy.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

output "deploy_role_arn" {
  description = "GitHub Actions role used for deployment from main."
  value       = aws_iam_role.grc_deploy.arn
}

# Reuse the working state-lock and encryption-key permissions.
resource "aws_iam_role_policy" "deploy_state_access" {
  name   = "capstone-state-access"
  role   = aws_iam_role.grc_deploy.id
  policy = aws_iam_role_policy.grc_gate_state.policy
}

# Deployment must also save the updated Terraform state.
resource "aws_iam_role_policy" "deploy_state_write" {
  name = "capstone-state-write"
  role = aws_iam_role.grc_deploy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid      = "WriteTerraformState"
      Effect   = "Allow"
      Action   = "s3:PutObject"
      Resource = "${aws_s3_bucket.tfstate.arn}/capstone/terraform.tfstate"
    }]
  })
}

# Reuse the working evidence-upload permissions.
resource "aws_iam_role_policy" "deploy_evidence" {
  name   = "capstone-evidence-upload"
  role   = aws_iam_role.grc_deploy.id
  policy = aws_iam_role_policy.grc_gate_evidence.policy
}

# IAM for the roles and provider this stack manages. PowerUserAccess does not
# include IAM writes. Actions stay enumerated and resources stay on these ARNs
# so the least-privilege Rego check can read the document.
resource "aws_iam_role_policy" "deploy_iam" {
  name = "capstone-workload-iam"
  role = aws_iam_role.grc_deploy.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ManageStackRoles"
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:DeleteRole",
          "iam:GetRole",
          "iam:UpdateRole",
          "iam:UpdateAssumeRolePolicy",
          "iam:TagRole",
          "iam:UntagRole",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:ListInstanceProfilesForRole",
          "iam:PutRolePolicy",
          "iam:GetRolePolicy",
          "iam:DeleteRolePolicy",
        ]
        Resource = [
          aws_iam_role.grc_gate.arn,
          aws_iam_role.grc_deploy.arn,
          aws_iam_role.lambda.arn,
          aws_iam_role.config.arn,
        ]
      },
      {
        Sid    = "AttachKnownPolicies"
        Effect = "Allow"
        Action = [
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
        ]
        Resource = [
          aws_iam_role.grc_gate.arn,
          aws_iam_role.grc_deploy.arn,
          aws_iam_role.lambda.arn,
          aws_iam_role.config.arn,
        ]
        Condition = {
          ArnEquals = {
            "iam:PolicyARN" = [
              "arn:aws:iam::aws:policy/ReadOnlyAccess",
              "arn:aws:iam::aws:policy/PowerUserAccess",
              "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
              "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole",
              "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole",
            ]
          }
        }
      },
      {
        Sid    = "PassStackRoles"
        Effect = "Allow"
        Action = "iam:PassRole"
        Resource = [
          aws_iam_role.lambda.arn,
          aws_iam_role.config.arn,
        ]
        Condition = {
          StringEquals = {
            "iam:PassedToService" = [
              "lambda.amazonaws.com",
              "config.amazonaws.com",
            ]
          }
        }
      },
      {
        Sid    = "ManageGitHubOidcProvider"
        Effect = "Allow"
        Action = [
          "iam:GetOpenIDConnectProvider",
          "iam:UpdateOpenIDConnectProviderThumbprint",
          "iam:AddClientIDToOpenIDConnectProvider",
          "iam:RemoveClientIDFromOpenIDConnectProvider",
          "iam:TagOpenIDConnectProvider",
          "iam:UntagOpenIDConnectProvider",
          "iam:DeleteOpenIDConnectProvider",
        ]
        Resource = local.github_oidc_arn
      },
      {
        Sid    = "CreateServiceLinkedRoles"
        Effect = "Allow"
        Action = [
          "iam:CreateServiceLinkedRole",
          "iam:TagRole",
        ]
        Resource = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:role/aws-service-role/*"
      },
    ]
  })
}