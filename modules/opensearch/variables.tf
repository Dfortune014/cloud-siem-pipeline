variable "opensearch_master_user" {
  description = "Master username for OpenSearch"
  type        = string
}

variable "opensearch_master_password" {
  description = "Master password for OpenSearch"
  type        = string
  sensitive   = true
}

variable "lambda_role_arn" {
  description = "ARN of Lambda execution role allowed to write to OpenSearch"
  type        = string
}