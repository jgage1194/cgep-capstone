.PHONY: deploy plan test destroy fmt creds

# Set AWS_PROFILE in your shell before running, or pass on the command line:
#   make deploy AWS_PROFILE=my-sandbox
AWS_PROFILE ?= default

# If your profile is AWS SSO-based, the Terraform provider can't always
# read the profile directly. Export credentials into env vars first.
CREDS = eval "$$(aws configure export-credentials --profile $(AWS_PROFILE) --format env)"

deploy: ## Deploy the starter (terraform init + apply)
	@$(CREDS) && cd terraform && terraform init -input=false -backend-config=backend.hcl && terraform apply -auto-approve

plan: ## Show what deploy would do
	@$(CREDS) && cd terraform && terraform init -input=false -backend-config=backend.hcl && terraform plan

test: ## Smoke test the deployed API
	@$(CREDS) && cd terraform && API_URL=$$(terraform output -raw api_url) && \
		echo "POST $$API_URL" && \
		curl -sS -X POST "$$API_URL" \
			-H 'content-type: application/json' \
			-d '{"patient_id":"P-0001","fields":{"reason":"smoke-test"}}' \
		| python3 -m json.tool

destroy: ## Tear it all down
	@$(CREDS) && cd terraform && terraform destroy -auto-approve

fmt:
	cd terraform && terraform fmt -recursive

creds: ## Print the active AWS identity (sanity check)
	@$(CREDS) && aws sts get-caller-identity
