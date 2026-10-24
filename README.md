# Acme Health — GRC Engineering Capstone

This project wraps a fictional patient-intake API with Terraform safeguards,
executable compliance policies, a gated deployment workflow, and signed evidence
in an S3 Object Lock vault. HIPAA Security Rule is the primary framework;
NIST SP 800-53, SOC 2, and CMMC references are supporting mappings.

Built on the [GRC Engineering Club starter](https://github.com/GRCEngClub/cgep-app-starter).
See [WORKLOAD.md](WORKLOAD.md) for the application and [WRITEUP.md](WRITEUP.md)
for design decisions, demonstrated runs, and tradeoffs. Use synthetic data only.

## Before and after

The original starter was a working patient-intake API with deliberately missing
safeguards. The capstone preserves that application and adds four governance
layers: Terraform safeguards, executable Rego policies, a GitHub Actions gate
with signed evidence, and OSCAL control documentation.

| Area | Original starter | Current capstone |
| --- | --- | --- |
| S3 intake encryption | SSE-S3 rather than the project's customer-managed key baseline | Explicit SSE-KMS configuration using a customer-managed key |
| DynamoDB encryption | Default AWS-owned key | Customer-managed KMS key |
| S3 transport | No bucket-policy denial of insecure requests | Explicit non-TLS denial on bucket and object actions |
| S3 recovery support | No versioning | Versioning enabled; independent backup and restore testing are outside this implementation |
| Lambda networking | No association with the provisioned workload VPC | Private subnet and security-group association, with S3 and DynamoDB gateway endpoints |
| Lambda visibility and resilience | No active X-Ray tracing, DLQ, or reserved concurrency | Active tracing and an encrypted SQS DLQ; reserved concurrency remains deferred pending quota approval |
| Application permissions | Broad `s3:*` and `dynamodb:*` actions | Enumerated application actions and scoped resources, with documented operational allowances |
| API protection | No access logging, configured throttling, or WAF | Structured access logs and throttling configured; WAF remains deferred |
| Change governance | Operator-driven deployment through the Makefile | Required PR policy checks and saved-plan apply on main, currently limited by deployment-role permissions |
| Evidence | No automated signed evidence vault workflow | Cosign-signed bundles, SHA-256 digests, receipts, S3 versioning and Object Lock |
| Control traceability | Starter gap list and framework mapping guidance | HIPAA-first policy metadata, implementation descriptions and evidence links in OSCAL |

“After” describes implemented configuration and workflow behavior, not complete
HIPAA compliance. Policy tests and the demonstrated workflow runs provide
specific evidence; behavior tests still outstanding and deferred safeguards are
documented in [WRITEUP.md](WRITEUP.md).

## Architecture

API Gateway accepts `POST /intake`. Lambda writes submissions to DynamoDB and
optional attachments to S3. Lambda is associated with private VPC subnets and
uses S3 and DynamoDB gateway endpoints. Terraform configures customer-managed
KMS encryption for the intake data stores, S3 TLS enforcement and versioning,
scoped application IAM permissions, API access logging and throttling, and
CloudTrail management-event logging.

GitHub Actions uses OIDC and separate gate and deployment roles. Evidence is
stored in a separate bucket within the same AWS account, with SSE-KMS,
versioning, blocked public access, and default Governance retention of 30 days.
The retention period and mode are configurable; check actual object retention
when verifying a run.

## Control coverage

| Gap | Policy | Primary HIPAA reference |
| --- | --- | --- |
| GAP-01: S3 encryption | [s3_encryption.rego](policies/s3_encryption.rego) | 164.312(a)(2)(iv) |
| GAP-02: DynamoDB encryption | [dynamodb_encryption.rego](policies/dynamodb_encryption.rego) | 164.312(a)(2)(iv) |
| GAP-03: S3 TLS enforcement | [s3_secure_transport.rego](policies/s3_secure_transport.rego) | 164.312(e)(1) |
| GAP-04: S3 versioning | [s3_versioning.rego](policies/s3_versioning.rego) | 164.308(a)(7) |
| GAP-05: Lambda VPC association | [lambda_vpc.rego](policies/lambda_vpc.rego) | 164.312(e)(1) |
| GAP-06: Lambda tracing, DLQ, concurrency | [lambda_resilience.rego](policies/lambda_resilience.rego) | 164.308(a)(1)(ii)(D), supporting safeguards |
| GAP-07: IAM permissions | [iam_least_privilege.rego](policies/iam_least_privilege.rego) | 164.312(a)(1) |
| GAP-08: API logging, throttling, WAF exception | [api_protection.rego](policies/api_protection.rego) | 164.312(b), logging |

These are selected implementations supporting the cited requirements, not a
claim of complete HIPAA compliance. GAP-06 and GAP-08 remain partially addressed.
Policy fixtures cover passing, failing, and edge-case inputs.

## Prerequisites and account setup

- Terraform 1.16.4, matching the workflow, and AWS CLI v2.
- OPA with Rego v1 support, or Conftest 0.50.0 for the workflow's unit-test command.
- Cosign 2.2.4 for the documented evidence verification flow, Bash, jq, and Git.
- Python 3 and curl for the application smoke test.
- For OSCAL validation and resolution: an installed `compliance-trestle` CLI.
- Authorized AWS credentials for the target account and relevant operations.

New accounts need a one-time state-storage bootstrap before the normal Makefile
commands can run. Follow [First deployment and shared state](docs/BOOTSTRAP.md)
for both fresh-account setup and reconnecting the existing deployment.

The backend settings live in ignored `terraform/backend.hcl`, rather than in the
committed Terraform configuration. GitHub Actions reads the same settings from
the `TF_BACKEND_CONFIG` repository variable. The workload can optionally create
the GitHub OIDC provider if the new account does not already have one.

For an existing configured sandbox, authenticate and export temporary credentials:

```bash
aws sts get-caller-identity --profile default
eval "$(aws configure export-credentials --profile default --format env)"
export TF_VAR_github_org="<github-org>"
export TF_VAR_github_repo="<github-repo>"
```

Use your own AWS profile and repository identity when adapting the project.
Exported credentials expire; refresh them when necessary.

## Deploy gate and Makefile commands

The original deploy gate still matters: the application must run before its
safeguards can be assessed. After completing the account setup above, use the
existing Makefile from the repository root:

```bash
make creds AWS_PROFILE=default
make plan AWS_PROFILE=default
make deploy AWS_PROFILE=default
make test AWS_PROFILE=default
```

`make deploy` is an operator bootstrap command: it runs Terraform apply with
`-auto-approve` and does not invoke the Rego gate. Review `make plan` first.
Normal changes should go through the gated PR and main deployment workflow.
`make plan` displays a plan but does not save `tfplan` for the local policy script.

The Makefile exports temporary AWS credentials for the selected profile, including
SSO-backed profiles. This avoids the provider's `failed to find SSO session
section` problem encountered in the labs. For direct Terraform commands, use
the credential-export command above and refresh credentials when they expire.

Expected response from `make test`:

```json
{
  "submission_id": "<generated UUID>",
  "status": "received"
}
```

`make fmt` formats Terraform. `make destroy AWS_PROFILE=default` invokes immediate
teardown with `-auto-approve`; read the cleanup section before using it because
Object Lock, retained versions, and the vault policy affect deletion.

## Local checks

Run from the repository root:

```bash
terraform -chdir=terraform fmt -check -recursive
terraform -chdir=terraform init -input=false -backend-config=backend.hcl
terraform -chdir=terraform validate
opa check --strict policies
opa test policies -v
```

To use the same unit-test runner as CI:

```bash
conftest verify --policy policies
```

To evaluate a fresh plan against the policies without applying it:

```bash
terraform -chdir=terraform plan -input=false -out=tfplan
bash scripts/policy-gate.sh --workspace terraform --policy policies
```

The gate exports `terraform/plan.json` and writes
`evidence/capstone/conftest-results.json`. Its local `--all-namespaces` option can
include empty results for test namespaces; the CI workflow explicitly selects
the eight enforcement namespaces. Policy unit tests are run separately.
Do not commit saved plans, state, or generated evidence.

To exercise the deployed API with synthetic intake data:

```bash
bash test/intake.sh
```

The smoke test checks the basic response; it is not a full behavioral test of
logging, encryption, throttling, tracing, or asynchronous failure delivery.

## GitHub Actions

Configure these GitHub Actions repository variables:

| Variable | Value |
| --- | --- |
| `AWS_ROLE_ARN` | Existing gate role ARN, available as Terraform output `role_arn` |
| `AWS_DEPLOY_ROLE_ARN` | Existing deployment role ARN, output `deploy_role_arn` |
| `EVIDENCE_VAULT` | Evidence bucket name, output `vault_name` |
| `TF_BACKEND_CONFIG` | Contents of local `terraform/backend.hcl` |
| `CREATE_GITHUB_OIDC_PROVIDER` | `true` only if this stack created the provider; otherwise unset/false |

The [workflow](.github/workflows/grc-gate.yml) runs on PRs to `main`, pushes to
`main`, and manual dispatch. Configure a branch ruleset requiring its successful
check before merging; branch protection is a GitHub setting, not defined by the
workflow YAML alone.

1. Run policy unit tests, initialize and validate Terraform, and save a plan.
2. Evaluate the plan using the eight capstone policy namespaces.
3. On a successful push run on `main`, apply that same saved plan. PR and manual
   runs skip apply. The main run generates its own plan; it does not reuse the PR plan.
4. Bundle available policy results, plan outputs, and apply output; hash and sign
   the bundle with Cosign; upload it and a receipt to the evidence vault.
5. Preserve GitHub artifacts for 90 days and report PR findings. Evidence steps
   are attempted even after earlier failures. Required evidence steps must succeed.

The deployment role currently supports updates to the existing Lambda and state
and evidence operations. A plan requiring other write permissions will fail;
expanding the role remains planned work. Advisory warnings do not block apply.
The workflow currently uses Conftest; tfsec is deferred.

## Assessor walkthrough

Start with [the OSCAL component](oscal/components/compliant-acme.json). Each
implemented requirement includes its HIPAA citation, implementation description,
secondary mappings, evidence links, and limitations. The
[source catalog](oscal/catalogs/hipaa-security-rule.json) contains seven selected
HIPAA safeguards. The [profile](oscal/profiles/cge-p-minimum.json) selects them;
its [resolved catalog](oscal/catalogs/cge-p-minimum-resolved.json) contains their text.
This is a custom subset, not an official complete HIPAA catalog.

Demonstrated evidence:

- [Successful deployment: 40017405490](https://github.com/jgage1194/cgep-capstone/actions/runs/40017405490)
- [Rejected versioning change: 40018585656](https://github.com/jgage1194/cgep-capstone/actions/runs/40018585656)

With authorized AWS access, verify a run from the repository root:

```bash
bash scripts/verify-evidence.sh 40017405490 \
  --vault acme-health-intake-grc-evidence-vault-acf20522 \
  --profile default
```

The verifier downloads the bundle, compares its SHA-256 digest, verifies the
Cosign signature using the GitHub Actions issuer, and checks unexpired retention.
Success prints `CHAIN INTACT for run 40017405490`. An evidence link grants no
access. The assessor needs S3 listing/read and retention-read permissions and
KMS decryption access. Dependencies and Cosign trust services must be available.

Current limits: signing identity is not restricted to this workflow; downloads
and retention checks target the current key rather than pinning the receipt's
version ID; expired retention causes verification to fail even if the signature
is valid. Chain verification does not prove ongoing control effectiveness.

For current configuration alignment, use the merged configuration, correct
backend, variables, provider lockfile, and credentials, then generate a fresh
`terraform plan -detailed-exitcode`. Exit 0 means no proposed changes were found
for the resources Terraform evaluated; exit 2 indicates changes and exit 1 an
error. It does not establish compliance for unmanaged resources.

## Limitations and follow-up

- WAF protection and reserved concurrency remain documented exceptions.
- Logs and tracing are configured, but targeted operational detections, alert
  routing, and recurring drift checks have not yet been implemented.
- tfsec is disabled; the rubric's other scanners have not yet been verified.
- Deployment-role permissions do not yet cover the full workload lifecycle.
- See [WRITEUP.md](WRITEUP.md) for behavior tests still outstanding and design tradeoffs.

## Repository layout

| Path | Purpose |
| --- | --- |
| `terraform/` | Workload, safeguards, evidence vault, backend and pipeline roles |
| `policies/` | Eight Rego policies and their test fixtures in `policies/tests/` |
| `.github/workflows/grc-gate.yml` | Policy gate, main deployment and signed evidence |
| `scripts/` | Local policy evaluation, capture and evidence verification |
| `oscal/` | HIPAA subset catalog, profile, resolved catalog and component |
| `test/intake.sh` | Synthetic application smoke test |
| `Makefile` | Credential, plan, deployment, test, format and teardown shortcuts |
| `WRITEUP.md` | Design rationale, evidence walkthrough and deferred work |

The original [gap inventory](GAPS.md) and [framework mapping primer](FRAMEWORKS.md)
remain available. The course's full brief is
`docs/labs/07_01_capstone_brief.md` in its course content repository.

## Cost

This completed deployment adds customer-managed KMS keys, logs, state storage,
and retained evidence to the starter. Costs depend on usage, retention and AWS
pricing; the starter's near-zero short-lived estimate is not a budget for this
expanded environment. Account for retained objects during cleanup.

## Cleanup

Object Lock and the bucket-deletion policy make cleanup different from a normal
starter teardown. Review retention and IAM permissions before destroying this
sandbox. Do not assume `make destroy` can remove the vault or retained object
versions. Never destroy a shared backend while it is still in use.

## Attribution and license

Original workload: [GRC Engineering Club / cgep-app-starter](https://github.com/GRCEngClub/cgep-app-starter),
whose README declares MIT licensing. Capstone additions by James Gage.
See [LICENSE](LICENSE). Preserve upstream notices when redistributing the starter.
