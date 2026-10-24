#!/usr/bin/env bash
# First-time setup only, in a fresh clone. Uses the workload's existing state
# resources so there is one owner and no resource-address migration later.
set -euo pipefail
umask 077
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TF_DIR="$ROOT/terraform"
for command in terraform python3; do
  command -v "$command" >/dev/null || { echo "Missing $command" >&2; exit 2; }
done
# Never switch an initialized deployment to local state or overwrite its config.
for path in .terraform terraform.tfstate terraform.tfstate.backup backend.hcl bootstrap_override.tf bootstrap.tfplan; do
  [[ ! -e "$TF_DIR/$path" ]] || {
    echo "Refusing bootstrap: terraform/$path exists. Use a fresh clone for a new deployment." >&2
    exit 2
  }
done
: "${TF_VAR_github_org:?Set TF_VAR_github_org}"
: "${TF_VAR_github_repo:?Set TF_VAR_github_repo}"
# The local backend exists only during initial state-storage provisioning.
# Leave it and the local state in place if anything fails, for manual recovery.
cat > "$TF_DIR/bootstrap_override.tf" <<'HCL'
terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}
HCL
terraform -chdir="$TF_DIR" init -input=false
terraform -chdir="$TF_DIR" plan -input=false -out=bootstrap.tfplan \
  -target=aws_s3_bucket_versioning.tfstate \
  -target=aws_s3_bucket_public_access_block.tfstate \
  -target=aws_s3_bucket_server_side_encryption_configuration.tfstate \
  -target=aws_s3_bucket_policy.tfstate
printf '\nCreate only the planned backend resources and dependencies? Type yes: '
read -r response
[[ "$response" == yes ]] || { echo "Stopped. Bootstrap files retained; no apply performed."; exit 1; }
terraform -chdir="$TF_DIR" apply -input=false bootstrap.tfplan
# Read only the required identifiers, without displaying the full state.
python3 - "$TF_DIR" <<'PY'
import json, subprocess, sys
from pathlib import Path
p=Path(sys.argv[1])
d=json.loads(subprocess.check_output(['terraform',f'-chdir={p}','show','-json'],text=True))
rs={r['address']:r['values'] for r in d['values']['root_module']['resources']}
bucket=rs['aws_s3_bucket.tfstate']['bucket']
arn=rs['aws_kms_key.evidence']['arn'];region=arn.split(':')[3]
with (p/'backend.hcl').open('x') as f:
 for k,v in {'bucket':bucket,'key':'capstone/terraform.tfstate','region':region,'kms_key_id':arn}.items():
  f.write(f'{k} = {json.dumps(v)}\n')
 f.write('encrypt = true\nuse_lockfile = true\n')
PY
rm "$TF_DIR/bootstrap_override.tf"
echo "Terraform will now ask to copy the local state into the new S3 backend. Answer yes."
# Do not use -reconfigure: this transition must copy the existing bootstrap state.
terraform -chdir="$TF_DIR" init -migrate-state -backend-config=backend.hcl
rm -f "$TF_DIR/bootstrap.tfplan"
echo "Backend initialized. Keep local state backups private until migration is confirmed."
echo "Next: terraform -chdir=terraform plan (without -target) to review the full workload."
echo "Configure GitHub variable TF_BACKEND_CONFIG with the contents of terraform/backend.hcl."
