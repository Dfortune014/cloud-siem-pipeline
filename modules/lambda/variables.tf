variable "sns_topic_arn" {
  description = "ARN of the SNS topic for alerts"
  type        = string
}

variable "opensearch_endpoint" {
  description = "OpenSearch domain endpoint"
  type        = string
}

variable "opensearch_user" {
  description = "OpenSearch master username"
  type        = string
}

variable "opensearch_pass" {
  description = "OpenSearch master password"
  type        = string
  sensitive   = true
}