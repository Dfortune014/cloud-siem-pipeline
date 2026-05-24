variable "alert_email" {
  description = "Your email for alerts"
  type        = string
}

variable "opensearch_master_user" {
  description = "Master username for OpenSearch"
  type        = string
}

variable "opensearch_master_password" {
  description = "Master password for OpenSearch"
  type        = string
  sensitive   = true
}