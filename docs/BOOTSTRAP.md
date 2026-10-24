# First deployment and shared Terraform state

Terraform must initialize its backend before creating the resources in a plan.
This project therefore starts a new deployment with local state, provisions only
the state-storage resources and dependencies, and then migrates that state to S3.
The targeted plan is a one-time bootstrap exception. All later plans are untargeted.

## Existing deployment (the current capstone)

Do **not** run `bootstrap-state.sh` against an existing deployment. It refuses an
initialized directory or an existing backend settings file.

The packaging update moves the same backend identifiers out of `main.tf` into
`terraform/backend.hcl`; no bucket, state key or encryption key changes. Preserve
that file locally and set the GitHub variable before running the updated workflow:

```bash
gh variable set TF_BACKEND_CONFIG \
  --repo '<github-org>/<github-repo>' < terraform/backend.hcl
terraform -chdir=terraform init -input=false -backend-config=backend.hcl
terraform -chdir=terraform plan
```

Inspect the plan before applying. The OIDC change defaults to looking up the
existing provider; changing the data lookup's address does not recreate the
account's provider. Do not set `create_github_oidc_provider=true` in this account.
Do not use `-migrate-state` or `-reconfigure` for this unchanged-backend update.

## New deployment in another account

Use a fresh clone, Terraform 1.16.4, AWS CLI v2, Python 3 and Bash. The operator
needs permissions to create the workload and its IAM, KMS and S3 resources.
This path intentionally requires reviewing the plan and confirming creation.

```bash
git clone https://github.com/<github-org>/<github-repo>.git
cd <github-repo>
eval "$(aws configure export-credentials --profile <aws-profile> --format env)"
aws sts get-caller-identity
export TF_VAR_github_org='<github-org>'
export TF_VAR_github_repo='<github-repo>'
cp terraform/terraform.tfvars.example terraform/terraform.tfvars
```

Edit `terraform/terraform.tfvars` with the same owner and repository. This example
uses `us-east-1`, matching the current KMS service conditions and workflow. Region
portability is separate work.

Check whether the account already has the GitHub provider, using the account ID
from `get-caller-identity`:

```bash
aws iam get-open-id-connect-provider \
  --open-id-connect-provider-arn \
  'arn:aws:iam::<account-id>:oidc-provider/token.actions.githubusercontent.com'
```

If it exists, leave `create_github_oidc_provider=false`. If AWS returns
`NoSuchEntity`, set it to `true` in `terraform.tfvars`. Other errors, such as
`AccessDenied`, do not prove that the provider is absent. If this stack creates
the provider, keep that setting true for its lifecycle.

Run the bootstrap and answer its confirmation prompts:

```bash
bash scripts/bootstrap-state.sh
```

The bootstrap creates the state bucket's versioning, public-access block,
encryption configuration and TLS policy, plus the required bucket, random suffix
and evidence KMS key. It writes ignored `terraform/backend.hcl`, switches from
local to S3 state using Terraform's migration prompt, and retains private local
state backups for recovery. Do not commit those backups.

If interrupted, preserve the local state and initialization metadata. Do not
restart in a second clone: that could create a different stack. Diagnose the
failed step and complete migration using the existing state. A local backend
override remains in place if provisioning fails before migration; do not delete
it or the local state to get past an error.

Next, review and deploy the entire workload:

```bash
make plan AWS_PROFILE=<aws-profile>
make deploy AWS_PROFILE=<aws-profile>
make test AWS_PROFILE=<aws-profile>
```

`make deploy` uses operator credentials and applies directly; normal subsequent
changes belong in the PR workflow. The bootstrap's targeted plan does not establish
that the full workload deployed or that the compliance gate passed.

## Configure GitHub Actions

Configure the existing `AWS_ROLE_ARN`, `AWS_DEPLOY_ROLE_ARN` and `EVIDENCE_VAULT`
variables from Terraform outputs, then set the backend configuration:

```bash
gh variable set TF_BACKEND_CONFIG \
  --repo '<github-org>/<github-repo>' < terraform/backend.hcl
```

Backend configuration contains resource identifiers, never credentials. It is
kept out of Git but must be available to every runner using the shared state.
If the stack created the GitHub provider, also run:

```bash
gh variable set CREATE_GITHUB_OIDC_PROVIDER \
  --repo '<github-org>/<github-repo>' --body true
```

If reusing an existing provider, leave that variable unset (defaults false).
Configure branch protection separately. Deployment-role write permissions still
cover only the previously documented operations; this backend update does not
expand them.
