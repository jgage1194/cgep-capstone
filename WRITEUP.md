# Acme Health: GRC Engineering Capstone Write-up

## Primary framework

The primary framework choice for Acme Health is the HIPAA Security Rule.
This is because the HIPAA Security Rule is a requirement for covered
entities maintaining or transmitting ePHI. Acme Health falls under this
category as a telehealth company. Acme Health should focus on compliance
requirements that it already has instead of pursuing compliance with
additional frameworks. While SOC 2 Type II is a nice to have when selling
to enterprise customers, Acme Health currently has one customer expressing
interest in a SOC 2 Type II report. If customer demand continues to grow then
attaining a SOC 2 Type II report should be revisited. As for CMMC, a federal
pilot alone does not establish a CMMC Level 2 requirement. I would assess the
applicable contract requirements and information handled before determining the
required scope.

## Control coverage

The gap descriptions below describe the original starter.
The status column reflects the current implementation.

Status refers to remediation of the named starter configuration
gap, not complete implementation of the associated HIPAA
requirement. The OSCAL component documents supporting measures
and remaining limitations.

| ID     | Gap                                                                                                                                                | Where                               | Frameworks the gap implicates  | Closure Method       | Status                                                             |
| ------ | -------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------- | ------------------------------ | -------------------- | ------------------------------------------------------------------ |
| GAP-01 | S3 uploads bucket relies on AWS-managed SSE-S3 (the 2023 default) instead of SSE-KMS with a customer CMK. PHI keys are not under customer custody. | `aws_s3_bucket.uploads`             | HIPAA 164.312(a)(2)(iv)        | Terraform and Policy | Closed                                                             |
| GAP-02 | DynamoDB submissions table uses the AWS-owned default encryption key, not a CMK you control.                                                       | `aws_dynamodb_table.intake`         | HIPAA 164.312(a)(2)(iv)        | Terraform and Policy | Closed                                                             |
| GAP-03 | S3 uploads bucket has no policy denying non-TLS requests (no `aws:SecureTransport` deny).                                                          | `aws_s3_bucket.uploads`             | HIPAA 164.312(e)(1)            | Terraform and Policy | Closed                                                             |
| GAP-04 | S3 uploads bucket has no versioning. PHI overwrites are unrecoverable.                                                                             | `aws_s3_bucket.uploads`             | HIPAA 164.308(a)(7)            | Terraform and Policy | Closed                                                             |
| GAP-05 | Lambda runs in the default Lambda environment, not in the VPC the starter provisions.                                                              | `aws_lambda_function.intake`        | HIPAA 164.312(e)(1)            | Terraform and Policy | Closed                                                             |
| GAP-06 | No reserved concurrency, no DLQ, no X-Ray.                                                                                                         | `aws_lambda_function.intake`        | HIPAA 164.308(a)(1)(ii)(D)     | Terraform and Policy | Closed. Reserved concurrency is 5.                                 |
| GAP-07 | Lambda IAM role has `dynamodb:*` and `s3:*` on the workload resources. Wildly over-broad.                                                          | `aws_iam_role_policy.lambda_inline` | HIPAA 164.312(a)(1)            | Terraform and Policy | Closed                                                             |
| GAP-08 | API Gateway has no access logging, no throttling, no WAF.                                                                                          | `aws_apigatewayv2_stage.default`    | HIPAA 164.312(b)               | Terraform and Policy | Partially Closed. No WAF - Exception documented                    |

## Design decisions

### AWS Region: US-East-1

I kept the workload in us-east-1 to reuse my existing lab environment
and keep the capstone manageable. This avoids the complexity of a
multi-region deployment, but the project does not demonstrate recovery
from a regional outage.

### Object Lock mode: GOVERNANCE

I chose Governance mode to protect retained evidence while keeping
cleanup practical for a temporary capstone environment. Governance
retention can be bypassed by a principal with explicit bypass
permission; ordinary delete permissions are insufficient.

For a production evidence vault, I would choose Compliance mode
after defining the retention requirements. That would prevent
deletion of protected object versions or shortening their retention
period, even by the account root user, until retention expires.
The tradeoff is that mistakes cannot be undone simply to clean up
the environment.

### Deployment: Apply on merge

I chose apply on merge because I trust the pipeline's tested checks
and the limited impact of changes in this capstone environment.
Required checks prevent merging changes that fail the policy gate.
After merge, the workflow evaluates a fresh saved plan before
applying that same plan.

The deployment role applies every change in the saved Terraform
plan after the policy gate passes. PowerUserAccess covers the
non-IAM resources. The inline IAM policy covers the roles this
stack manages.

I accepted automated deployment without an additional manual
approval step. Passing policy checks provides confidence in the
specific conditions tested; it does not guarantee that every
change is secure or functionally correct.

### Remote state

Terraform state lives in the S3 bucket this stack creates. GitHub Actions
and a local operator share that state. The committed configuration only
declares `backend "s3" {}`. The bucket, key, and encryption settings are
in ignored `terraform/backend.hcl` and in the `TF_BACKEND_CONFIG`
repository variable, so the repository does not name the state bucket
and does not contain credentials.

A grader does not need this account's state. `terraform init -backend=false`
and `terraform validate` check the configuration on their own. The Rego
suite runs against fixtures, and a gap check can plan a copy of this
configuration in another account. The shared backend matters for the
GitHub deployment, which is what produces the signed evidence runs.

### Single AWS Account

I used one AWS account for the workload, deployment pipeline roles,
and evidence vault to simplify setup and administration. Separate
IAM roles distinguish policy evaluation from deployment, but they
do not provide account-level isolation.

For a production implementation, I would consider placing the
evidence vault in a separate security or audit account to reduce
the workload account's ability to affect retained evidence.

### Terraform and policy checks

Terraform configures the safeguards, while Rego policies evaluate
the proposed Terraform plan for the conditions I want to enforce.
Using both lets me implement a safeguard and detect later changes
that would remove or weaken it.

I made the S3 checks apply to every managed bucket in the plan
rather than specific bucket names. This allows new buckets to
receive the same checks without requiring a new policy for each.

Blocking findings stop the deployment path. The deferred WAF
exception produces a warning so it stays visible without preventing
deployment.

The tradeoff is maintaining both the infrastructure configuration
and the policy logic. Tests help verify that the policies accept
expected configurations and reject the specific failures they
were designed to catch.

## How the pipeline produces evidence

A pull request targeting main starts the GRC workflow. The workflow
authenticates to AWS through OIDC, runs the policy unit tests,
validates Terraform, and creates a saved plan. Conftest evaluates
that plan against the nine capstone policy namespaces.

Blocking findings fail the required check and prevent merging.
Documented warnings remain visible without blocking deployment.
Pull-request runs do not apply infrastructure changes.

After merge, a push to main starts a new workflow run using the
deployment role. It generates and evaluates a fresh saved plan,
then applies that exact plan if the preceding checks succeed.

The workflow collects the policy test results, policy findings,
and available plan and apply outputs into an evidence bundle.
It calculates a SHA-256 digest, signs the bundle with Cosign,
and uploads the bundle, digest, and signature bundle to the
evidence vault under `runs/<run_id>/`. The vault's default Object
Lock retention protects the uploaded object versions.

A separate receipt records the run ID, commit SHA, bundle key,
object version ID, and digest. The workflow also uploads a GitHub
artifact for convenient review. Evidence collection is attempted
even when earlier checks fail, preserving available failure results.

### How an assessor follows the evidence

An assessor can start at oscal/components/compliant-acme.json,
select a HIPAA requirement, review its implementation description
and limitations, and follow its GitHub run or S3 evidence link.
The catalog provides the selected requirement text. Vault access
must be authorized separately; an evidence link does not grant
access.

### Demonstrated runs

- [Successful post-merge deployment: 40017405490](https://github.com/jgage1194/cgep-capstone/actions/runs/40017405490)
- [Rejected S3 versioning change: 40018585656](https://github.com/jgage1194/cgep-capstone/actions/runs/40018585656)

I verified both evidence chains using scripts/verify-evidence.sh.
An assessor with authorized vault access can repeat the verification:

```bash
bash scripts/verify-evidence.sh 40017405490 \
  --vault acme-health-intake-grc-evidence-vault-acf20522 \
  --profile default
```

The script checks the bundle digest, verifies its Cosign signature
against the GitHub Actions OIDC issuer, and checks that the bundle
has an unexpired retention date. Successful verification prints:

```text
CHAIN INTACT for run 40017405490
```

This verifies the evidence bundle's integrity, signature, and
current retention. It does not independently establish that every
control is effective or that the deployed environment has remained
unchanged since the run.

## Trade-offs and what I'd do with another sprint

### Custom HIPAA OSCAL catalog

Choosing HIPAA as the primary framework meant creating a custom
OSCAL catalog for the seven selected safeguards, rather than
directly importing controls from the available NIST SP 800-53
catalog.

This keeps the requirements and implementation descriptions
organized around Acme Health's primary compliance obligation.
Supporting NIST SP 800-53, SOC 2, and CMMC references remain
secondary mappings.

The tradeoff is maintaining the selected requirement text,
identifiers, and mappings myself. The catalog is a project-authored
subset, not an official or complete HIPAA catalog. Trestle validation
confirms its OSCAL structure; it does not establish the accuracy
or completeness of its regulatory content or mappings.

With more time, I would expand this subset into a complete OSCAL
catalog of the HIPAA Security Rule, including its standards and
implementation specifications. I would verify the content against
the regulation, document its version and sources, and review the
supporting framework mappings.

The capstone profile would continue selecting only the safeguards
relevant to this project from that broader catalog.

### GAP-06: Reserved concurrency

I configured an encrypted dead-letter queue, active X-Ray tracing,
and reserved concurrency of five. The first attempt failed because
the account quota was 10 and AWS keeps 10 executions unreserved.
The quota increase has been approved, so the limit of five is set
and the policy now blocks a plan that removes it.

Tracing and asynchronous DLQ delivery still need separate behavior
tests. The normal intake smoke test does not exercise those features.

### GAP-08: WAF protection deferred

I implemented API access logging and throttling and verified that
successful intake requests appear in the access logs. Throttling
behavior still needs testing.

I deferred WAF protection. The starter uses an HTTP API, which does
not support direct AWS WAF association. Keeping that API would require
CloudFront with WAF and an additional mechanism to reject requests
that bypass CloudFront. I chose to limit the project's complexity.
The additional cost has not been evaluated.

With another sprint, I would implement and test both WAF filtering
and origin-bypass protection. GAP-08 remains partially addressed.

### OIDC and GitHub Actions

The policy gate and deployment workflow use separate AWS roles.
Pull-request runs use the gate role; pushes to main use the
deployment role. Both authenticate through GitHub OIDC without
stored AWS access keys.

The gate role retains the lab's repository-scoped trust pattern.
This simplifies setup but allows multiple workflow contexts within
the repository to assume it. Restricting trust further is future
hardening work.

The evidence verifier checks the GitHub Actions signing issuer
but currently accepts any certificate identity from that issuer.
A future improvement would restrict verification to this
repository's specific workflow identity.

### Deployment permissions

The main deployment role can apply this configuration. PowerUserAccess
covers the VPC, data stores, KMS keys, logging, Config, EventBridge,
and S3 changes. An inline policy covers IAM for the gate role, the
deployment role, the Lambda role, and the Config role, including
passing those roles only to Lambda and Config. Managed-policy
attachment is limited to the five policies this stack uses.

PowerUserAccess is account-wide, so the role can change non-IAM
resources that Terraform does not manage. I accepted that instead of
maintaining an action list that would miss the next resource.
AdministratorAccess is not attached. Creating the account's GitHub
OIDC provider still needs a local apply, because that create action
cannot be limited to one provider ARN.

### Activity review alerts

I enabled AWS Config with the lab pattern: one recorder for supported
resources, including global resource types, delivering history to an
encrypted and versioned bucket. An account can keep only one recorder
in a Region, so a recorder left over from the lab has to be removed
before this one can be created.

A managed Config rule checks that S3 buckets keep server-side
encryption. EventBridge publishes two alerts to one SNS topic. The
first matches read-write CloudTrail calls named StopLogging,
DeleteTrail, PutBucketEncryption, and DeleteBucketEncryption. The
second matches a change to NON_COMPLIANT on that Config rule. Those
event lists are the noise control. The topic is the alert route.
`alert_email` subscribes an operator; I left it empty so the topic
does not wait on an unconfirmed address.

### Checkov high findings

I enabled point-in-time recovery on the submissions table so intake
records have a continuous backup.

I replaced the inline Lambda VPC policy with the AWS managed
`AWSLambdaVPCAccessExecutionRole`. The previous policy allowed
network-interface actions on every resource. Lambda cannot restrict
those ENI actions to specific ARNs, and the managed policy is the
supported way to grant them.

I did not configure AWS Signer for the intake function. Code signing
needs a signing profile and a signed deployment package. Checkov
`CKV_AWS_272` is skipped on `aws_lambda_function.intake` for that
reason.

### Additional Scanning

I deferred tfsec scanning after reviewing its findings. The
current pipeline enforces the custom Rego policies but does not
run tfsec. Reintroducing a maintained scanner and reviewing its
findings remains follow-up work.

## What I didn't get to

WAF protection, Lambda code signing, and a scheduled drift check
remain deferred, with the reasons and follow-up work documented above.
