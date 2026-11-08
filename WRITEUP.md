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
| GAP-06 | No reserved concurrency, no DLQ, no X-Ray.                                                                                                         | `aws_lambda_function.intake`        | HIPAA 164.308(a)(1)(ii)(D)     | Terraform and Policy | Lambda closed at concurrency 5. Alerts are deployed; no subscriber or drift schedule. |
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

The deployment role applies the non-IAM changes in the saved Terraform
plan after the policy gate passes. PowerUserAccess covers those
resources. Inline IAM policies and trust policies are outside that
role, so a main-branch job cannot expand them.

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
The component's successful-deployment links point at run
42499992586. Its rejection links still point at run 40018585656.
The catalog provides the selected requirement text.
Vault access must be authorized separately; an evidence link does
not grant access.

### Demonstrated runs

- [Current deployment: 42499992586](https://github.com/jgage1194/cgep-capstone/actions/runs/42499992586)
- [Earlier successful deployment: 40017405490](https://github.com/jgage1194/cgep-capstone/actions/runs/40017405490)
- [Rejected S3 versioning change: 40018585656](https://github.com/jgage1194/cgep-capstone/actions/runs/40018585656)

Run 42499992586 is the current configuration. The gate passed, and the
main apply set reserved concurrency to five, created the alert key, and
replaced the deployment role's inline IAM policy. It then signed and
uploaded the bundle. Run 40017405490 is the earlier gated deployment.
Run 40018585656 is the plan the gate rejected for suspending S3
versioning.

I verified the earlier evidence chains with scripts/verify-evidence.sh.
An assessor with authorized vault access can verify the current run:

```bash
bash scripts/verify-evidence.sh 42499992586 \
  --vault acme-health-intake-grc-evidence-vault-acf20522 \
  --profile default
```

The script checks the bundle digest, verifies its Cosign signature
against the GitHub Actions OIDC issuer, and checks that the bundle
has an unexpired retention date. Successful verification prints:

```text
CHAIN INTACT for run 42499992586
```

Substitute an earlier run ID to verify that run. The vault name is the
same.

This verifies the evidence bundle's integrity, signature, and
current retention. It does not independently establish that every
control is effective or that the deployed environment has remained
unchanged since the run.

## Trade-offs

These are choices in the system as deployed. Work I left open is
in the next section.

### Custom HIPAA OSCAL catalog

Choosing HIPAA as the primary framework meant writing a catalog for
the seven safeguards this project implements. I kept the requirements
and descriptions organized around that obligation. NIST SP 800-53,
SOC 2, and CMMC stay secondary mappings.

I maintain the selected text, identifiers, and mappings myself. The
catalog is a project-authored subset of the HIPAA Security Rule.
Trestle validation confirms the OSCAL structure. It leaves the
accuracy of the regulatory text and the mappings as my responsibility.
A complete catalog, checked against the regulation and labeled with
its sources, was outside this project's scope. The profile would still
select only the safeguards this intake system uses.

### Reserved concurrency

I set reserved concurrency to five after AWS raised the account quota.
The first apply failed while the quota was 10, because Lambda keeps
10 executions unreserved. The dead-letter queue and active X-Ray
tracing are configured with that cap.

The Rego check requires a positive number. A later plan can change
five to another positive value and still pass. I did not encode the
specific value five into the policy.

### Keeping the HTTP API

I kept the starter's HTTP API. Access logging and throttling are
configured, and I verified that successful intake requests appear in
the access logs. AWS WAF cannot attach to an HTTP API directly, so
GAP-08 stays partial. The policy emits that as a warning, which keeps
the exception visible and lets a passing plan continue. How I would
close it is in the next section.

### Repository-scoped gate trust

Pull-request runs use the gate role. Pushes to main use the deployment
role. Both authenticate with GitHub OIDC and no stored access keys.
The gate trust matches any ref in this repository, which is the lab
pattern and lets a pull request plan without a tighter subject rule.
The evidence check accepts a signature from the GitHub Actions issuer.
Narrowing the trust and the signer identity is in the next section.

### Deployment permissions

PowerUserAccess lets the main role apply VPC, data, KMS, logging,
Config, EventBridge, and S3 changes. I used that managed policy so the
next non-IAM resource would not require a new action list. The role
can also change non-IAM resources this stack does not manage.
AdministratorAccess is not attached.

IAM stays narrower. The role can read the four stack roles, pass the
Lambda and Config roles only to those services, and attach only the
managed policy each role already uses. PowerUserAccess can be attached
only to the deployment role. The gate role, which any ref in this
repository can assume, can receive only ReadOnlyAccess. Inline-policy
writes, trust-policy updates, and permissions-boundary changes are
denied on all four roles. Run 42499992586 applied that policy. A later
main-branch job cannot put a broader inline policy onto these roles.
Creating the GitHub OIDC provider, or changing an inline policy or a
trust policy, takes a local apply.

### A short alert list

One Config recorder stores history for supported resources, including
global types, in an encrypted and versioned bucket. An account can
keep only one recorder in a Region, so a recorder left from the lab
has to be removed before this one can be created.

EventBridge publishes two alerts. One matches the read-write CloudTrail
calls StopLogging, DeleteTrail, PutBucketEncryption, and
DeleteBucketEncryption. The other matches a NON_COMPLIANT result from
the S3 server-side-encryption Config rule. I kept that list short so
ordinary changes do not page. `alert_email` is empty, so the topic
does not wait on an unconfirmed subscription.

The topic uses customer-managed key `alias/acme-health-control-alerts`.
EventBridge cannot publish to a topic encrypted with `alias/aws/sns`,
because that key policy does not allow `events.amazonaws.com` to
generate or decrypt data keys. This key allows EventBridge in this
account, and SNS for this topic, to do those operations.

### Findings I fixed, and scanners I left out

I enabled point-in-time recovery on the submissions table. I replaced
the inline Lambda VPC policy with `AWSLambdaVPCAccessExecutionRole`.
The inline policy allowed network-interface actions on every resource.
Lambda cannot restrict those actions to specific ARNs, so the managed
policy is the grant I kept.

Code signing and tfsec are not part of the gate. The gate enforces the
nine Rego policies through Conftest. Both leftovers are in the next
section.

## What I didn't get to

The safeguards, pipeline, and evidence chain above are in place.
Each item below is still open: what is missing, why I stopped, and
what would close it.

### WAF, and requests that skip it

GAP-08 has access logging and throttling. WAF is still an open
warning. The intake API is an HTTP API, so AWS WAF cannot attach to
it directly. Closing the exception means putting CloudFront in front
of the API, attaching a web ACL to that distribution, and rejecting
requests that reach the API without passing CloudFront. I have not
priced that path. Throttling is configured, and it still needs a test
that shows excess requests are rejected.

### Lambda code signing

Checkov `CKV_AWS_272` is skipped on `aws_lambda_function.intake`.
Closing it requires an AWS Signer signing profile and a signed
deployment package. I left both out of this capstone.

### A scheduled drift check

Config and EventBridge cover a short event list: stopping or deleting
the trail, changing S3 bucket encryption, and a NON_COMPLIANT result
on the S3 encryption rule. Nothing on a schedule compares the live
account with this Terraform configuration. The follow-up is a job that
runs `terraform plan -detailed-exitcode` and alerts when that plan
reports drift.

### Who can assume the gate role

Any workflow ref in this repository can assume `cgep-capstone-grc-gate`.
I kept the lab trust pattern so pull-request runs could plan without
a tighter subject rule. The follow-up is to limit that role to
pull-request workflows. Pushes to main would keep using the separate
deployment role.

### Which workflow may sign evidence

`scripts/verify-evidence.sh` checks that Cosign signed the bundle with
the GitHub Actions issuer. Any certificate identity from that issuer
currently satisfies the check. The follow-up is to require the
certificate identity for this repository's `grc-gate` workflow.

### tfsec

I reviewed tfsec's findings and left the scanner out of the workflow.
The gate enforces the nine Rego policies through Conftest. The
follow-up is to add a maintained scanner back and decide which of its
findings block a merge.

### Behavior the smoke test does not cover

`test/intake.sh` checks that a synthetic POST returns `received`.
X-Ray traces, delivery to the dead-letter queue, and API throttling
are configured and still need their own tests. Those tests are the
remaining proof for Lambda resilience and the API stage settings.
