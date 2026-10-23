variable "aws_region" {
  type        = string
  description = "AWS region for the starter."
  default     = "us-east-1"
}

# GRC baseline: Selects the evidence vault's Object Lock mode.
variable "lock_mode" {
  type        = string
  description = "Object Lock retention mode for deployment evidence."
  default     = "GOVERNANCE"

  validation {
    condition     = contains(["GOVERNANCE", "COMPLIANCE"], var.lock_mode)
    error_message = "lock_mode must be GOVERNANCE or COMPLIANCE."
  }
}

# GRC baseline: Sets the default retention period for new evidence objects.
variable "retention_days" {
  type        = number
  description = "Number of days to retain each new evidence object."
  default     = 30

  validation {
    condition = (
      var.retention_days >= 1 &&
      floor(var.retention_days) == var.retention_days
    )
    error_message = "retention_days must be a positive whole number."
  }
}