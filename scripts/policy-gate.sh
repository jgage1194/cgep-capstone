#!/usr/bin/env bash
# Usage: policy-gate.sh --workspace <path> [--policy <dir>]
# Requires an existing saved plan named tfplan. Does not plan or apply.
set -euo pipefail

POLICY_DIR="policies"
WORKSPACE=""
EVIDENCE_DIR="evidence/capstone"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace|--policy)
      [[ $# -ge 2 && -n "$2" && "$2" != --* ]] || {
        echo "Missing value for $1" >&2
        exit 2
      }

      case "$1" in
        --workspace) WORKSPACE="$2" ;;
        --policy) POLICY_DIR="$2" ;;
      esac

      shift 2
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

[[ -n "$WORKSPACE" && -d "$WORKSPACE" && -d "$POLICY_DIR" ]] || {
  echo "Usage: $0 --workspace <path> [--policy <dir>]" >&2
  exit 2
}

mkdir -p "$EVIDENCE_DIR"

# Remove previous outputs so a failed run cannot reuse stale results.
rm -f "$WORKSPACE/plan.json" "$EVIDENCE_DIR/conftest-results.json"

# Export the saved plan for policy evaluation.
terraform -chdir="$WORKSPACE" show -json tfplan \
  > "$WORKSPACE/plan.json"

# Reject missing or unexpected Terraform plan structure.
jq -e '
  (.format_version | type == "string") and
  (.resource_changes | type == "array")
' "$WORKSPACE/plan.json" > /dev/null

# Evaluate every capstone namespace and save one flat JSON report.
# Preserve Conftest's failure status while tee saves the results.
STATUS=0
conftest test "$WORKSPACE/plan.json" \
  --policy "$POLICY_DIR" \
  --all-namespaces \
  --output json \
  | tee "$EVIDENCE_DIR/conftest-results.json" || STATUS=$?

if [[ "$STATUS" -eq 0 ]]; then
  echo "policy-gate: PASS"
else
  echo "policy-gate: FAIL"
  echo "See $EVIDENCE_DIR/conftest-results.json"
fi

exit "$STATUS"