#!/usr/bin/env bash
# Validate the committed OSCAL catalog, profile, resolved catalog, and component.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

python3 -m venv "$work/venv"
"$work/venv/bin/pip" install --disable-pip-version-check 'compliance-trestle==5.2.0'

trestle_root="$work/trestle"
mkdir -p \
  "$trestle_root/.trestle" \
  "$trestle_root/catalogs/hipaa-security-rule" \
  "$trestle_root/catalogs/cge-p-minimum-resolved" \
  "$trestle_root/profiles/cge-p-minimum" \
  "$trestle_root/component-definitions/compliant-acme"

printf '[trestle]\nroot = .\n' > "$trestle_root/.trestle/config.ini"
cp "$root/oscal/catalogs/hipaa-security-rule.json" "$trestle_root/catalogs/hipaa-security-rule/catalog.json"
# The profile imports this path relative to profiles/cge-p-minimum/profile.json.
cp "$root/oscal/catalogs/hipaa-security-rule.json" "$trestle_root/catalogs/hipaa-security-rule.json"
cp "$root/oscal/catalogs/cge-p-minimum-resolved.json" "$trestle_root/catalogs/cge-p-minimum-resolved/catalog.json"
cp "$root/oscal/profiles/cge-p-minimum.json" "$trestle_root/profiles/cge-p-minimum/profile.json"
cp "$root/oscal/components/compliant-acme.json" "$trestle_root/component-definitions/compliant-acme/component-definition.json"

validate() {
  "$work/venv/bin/trestle" validate -tr "$trestle_root" -f "$1"
}

validate catalogs/hipaa-security-rule/catalog.json
validate catalogs/cge-p-minimum-resolved/catalog.json
validate profiles/cge-p-minimum/profile.json
validate component-definitions/compliant-acme/component-definition.json

echo "OSCAL models valid."
