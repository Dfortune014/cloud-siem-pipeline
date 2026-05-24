resource "aws_opensearch_domain" "siem" {
  domain_name    = "siem-events"
  engine_version = "OpenSearch_2.11"

  cluster_config {
    instance_type  = "t3.small.search"
    instance_count = 1
  }

  ebs_options {
    ebs_enabled = true
    volume_size = 10
    volume_type = "gp3"
  }

  node_to_node_encryption {
    enabled = true
  }

  encrypt_at_rest {
    enabled = true
  }

  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }

  advanced_security_options {
    enabled                        = true
    internal_user_database_enabled = true

    master_user_options {
      master_user_name     = var.opensearch_master_user
      master_user_password = var.opensearch_master_password
    }
  }

  tags = {
    Project = "cloud-siem-pipeline"
  }
}

resource "aws_opensearch_domain_policy" "siem" {
  domain_name = aws_opensearch_domain.siem.domain_name

  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = var.lambda_role_arn }
        Action    = "es:*"
        Resource  = "${aws_opensearch_domain.siem.arn}/*"
      },
      {
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::091855123856:user/siem-project-user" }
        Action    = "es:*"
        Resource  = "${aws_opensearch_domain.siem.arn}/*"
      },
      {
        Effect    = "Allow"
        Principal = { AWS = "*" }
        Action    = "es:*"
        Resource  = "${aws_opensearch_domain.siem.arn}/*"
        Condition = {
          IpAddress = {
            "aws:SourceIp" = ["68.35.124.19/32"]
          }
        }
      }
    ]
  })
}

output "opensearch_endpoint" {
  value = aws_opensearch_domain.siem.endpoint
}

output "opensearch_arn" {
  value = aws_opensearch_domain.siem.arn
}