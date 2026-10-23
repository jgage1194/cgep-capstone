# METADATA
# title: Require versioning on all managed S3 buckets
# description: Applies a consistent recovery baseline to every S3 bucket.
# custom:
#   framework: HIPAA Security Rule
#   controls:
#     - "164.308(a)(7)"
#   gap: GAP-04
#   severity: high
#   remediation: Attach an enabled versioning configuration to the bucket.
package compliance.s3_versioning

import rego.v1

# Match the bucket to an enabled versioning configuration.
s3_bucket_has_versioning(bucket) if {
    bucket_name := bucket.change.after.bucket
    is_string(bucket_name)
    bucket_name != ""

    some versioning in input.resource_changes
    versioning.mode == "managed"
    versioning.type == "aws_s3_bucket_versioning"
    versioning.change.after.bucket == bucket_name

    some configuration in versioning.change.after.versioning_configuration
    configuration.status == "Enabled"
}

# Discover all managed S3 buckets remaining in the proposed configuration.
deny_s3_versioning contains msg if {
    some bucket in input.resource_changes
    bucket.mode == "managed"
    bucket.type == "aws_s3_bucket"
    bucket.change.after != null

    not s3_bucket_has_versioning(bucket)

    msg := sprintf(
        "HIPAA 164.308(a)(7) | GAP-04 / GRC baseline: %s must have an associated S3 versioning configuration with status Enabled.",
        [bucket.address],
    )
}