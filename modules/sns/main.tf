resource "aws_sns_topic" "siem_alerts" {
  name = "guardrail-siem-alerts"
}

resource "aws_sns_topic_subscription" "email_alert" {
  topic_arn = aws_sns_topic.siem_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

output "topic_arn" {
  value = aws_sns_topic.siem_alerts.arn
}