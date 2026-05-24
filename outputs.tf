output "opensearch_endpoint" {
  value       = module.opensearch.opensearch_endpoint
  description = "OpenSearch domain endpoint"
}

output "opensearch_arn" {
  value       = module.opensearch.opensearch_arn
  description = "OpenSearch domain ARN"
}

output "sns_topic_arn" {
  value       = module.sns.topic_arn
  description = "SNS topic ARN for SIEM alerts"
}